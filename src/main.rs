extern crate lettre;
extern crate lettre_email;
extern crate recaptcha;

#[macro_use]
extern crate lazy_static;

use std::net::IpAddr;
use std::str::FromStr;
use actix_web::{error, middleware, web, App, Error, HttpResponse, HttpServer, HttpRequest, Result};
use actix_web::http::StatusCode;
use actix_web::dev::ServiceResponse;
use actix_http::{body::Body, Response};
use actix_web::middleware::errhandlers::{ErrorHandlerResponse, ErrorHandlers};
use actix_files as fs;
use tera::Tera;
use serde::Deserialize;
use lettre::{SmtpClient, Transport};
use lettre_email::Email;

mod settings;

async fn index(tmpl: web::Data<tera::Tera>) -> Result<HttpResponse, Error> {
    let config = settings::Settings::get();
    let mut context = tera::Context::new();
    context.insert("title", "Home");
    context.insert("recaptcha_site_key", config.recaptcha_site_key.clone().as_str());
    let s = tmpl.render("index.html", &context)
        .map_err(|_| error::ErrorInternalServerError("Template Error"))?;

    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

#[derive(Deserialize, Debug)]
struct Contact {
    name: String,
    email: String,
    message: String,
    recaptcha_response: String,
}

async fn index_post(req: HttpRequest, tmpl: web::Data<tera::Tera>, form: web::Form<Contact>) -> Result<HttpResponse, Error> {
    let config = settings::Settings::get();
    let conn_info = req.connection_info();
    let remote_ip_str = conn_info.remote().unwrap();
    let ip_addr = IpAddr::from_str(remote_ip_str.clone());
    let remote_ip = ip_addr.as_ref().ok();
    let res = recaptcha::verify(config.recaptcha_private.clone().as_str(), form.recaptcha_response.as_str(), remote_ip).await;

    let mut context = tera::Context::new();

    if res.is_ok() {
        let email_html = format!("<h1>New Contact Submission from your website.</h1><br/>Name : {}<br/>Email : {}<br/><br/>{}", form.name, form.email, form.message);
        let email_text = format!("New Contact Submission from your website.\nName : {}\nEmail : {}\n\n{}", form.name, form.email, form.message);
        let email = Email::builder()
            .to(config.contact_email.clone())
            .from((config.contact_from.clone(), config.contact_from_nicename.clone()))
            .reply_to(form.email.clone())
            .subject(format!("Contact Submission from {}", form.email.clone()))
            .alternative(email_html, email_text)
            .build()
            .unwrap();

        let mut mailer = SmtpClient::new_unencrypted_localhost().unwrap().transport();
        let result = mailer.send(email.into());

        let mut form_message = "Message sent successfully!";

        if result.is_ok() {
            println!("Email sent!");
        }
        else {
            println!("Could not send email: {:?}", result);
            form_message = "Could not send message. Try again later, or let me know on <a href='https://twitter.com/night_yagi/' target='_blank'>twitter</a>.";
        }

        context.insert("title", "Home");
        context.insert("form_message", form_message);
    }
    else {
        context.insert("title", "Home");
        context.insert("form_message", "There was a problem verifying the reCaptcha. Try again later, or let me know on <a href='https://twitter.com/night_yagi/' target='_blank'>twitter</a>.");
    }

    context.insert("recaptcha_site_key", config.recaptcha_site_key.clone().as_str());
    let s = tmpl.render("index.html", &context)
    .map_err(|_| error::ErrorInternalServerError("Template Error"))?;

    Ok(HttpResponse::Ok().content_type("text/html").body(s))
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    let tera = Tera::new(concat!(env!("CARGO_MANIFEST_DIR"),"/templates/**/*")).unwrap();

    HttpServer::new(move || {
        App::new()
            .data(tera.clone())
            .wrap(middleware::Logger::default())
            .service(fs::Files::new("/css", "./static/css").show_files_listing())
            .service(fs::Files::new("/js", "./static/js").show_files_listing())
            .service(fs::Files::new("/scss", "./static/sass").show_files_listing())
            .service(fs::Files::new("/images", "./static/images").show_files_listing())
            .service(fs::Files::new("/fonts", "./static/fonts").show_files_listing())
            .service(web::resource("/")
                .route(web::get().to(index))
                .route(web::post().to(index_post)))
            .service(web::scope("").wrap(error_handlers()))
    })
    .bind("127.0.0.1:8060")?
    .run()
    .await
}

// Custom error handlers, to return HTML responses when an error occurs.
fn error_handlers() -> ErrorHandlers<Body> {
    ErrorHandlers::new()
        .handler(StatusCode::NOT_FOUND, not_found)
        .handler(StatusCode::BAD_REQUEST, bad_request)
        .handler(StatusCode::METHOD_NOT_ALLOWED, not_allowed)
}

// Error handler for a 404 Page not found error.
fn not_found<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let response = get_error_response(&res, "Page not found");
    Ok(ErrorHandlerResponse::Response(
        res.into_response(response.into_body()),
    ))
}

// Error handler for a 404 Page not found error.
fn bad_request<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let response = get_error_response(&res, "Bad Request");
    Ok(ErrorHandlerResponse::Response(
        res.into_response(response.into_body()),
    ))
}

fn not_allowed<B>(res: ServiceResponse<B>) -> Result<ErrorHandlerResponse<B>> {
    let response = get_error_response(&res, "Not Allowed");
    Ok(ErrorHandlerResponse::Response(
        res.into_response(response.into_body()),
    ))
}


// Generic error handler.
fn get_error_response<B>(res: &ServiceResponse<B>, error: &str) -> Response<Body> {
    let request = res.request();

    // Provide a fallback to a simple plain text response in case an error occurs during the
    // rendering of the error page.
    let fallback = |e: &str| {
        Response::build(res.status())
            .content_type("text/plain")
            .body(e.to_string())
    };

    let tera = request.app_data::<web::Data<Tera>>().map(|t| t.get_ref());
    match tera {
        Some(tera) => {
            let mut context = tera::Context::new();
            context.insert("error", error);
            context.insert("status_code", res.status().as_str());
            let body = tera.render("error.html", &context);

            match body {
                Ok(body) => Response::build(res.status())
                    .content_type("text/html")
                    .body(body),
                Err(_) => fallback(error),
            }
        }
        None => fallback(error),
    }
}