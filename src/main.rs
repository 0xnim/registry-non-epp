use actix_web::{HttpResponse, error, get, post, delete, put, web, web::Json, App, Error, HttpServer, Responder};
use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{OpenOptions};
use std::fs::File;
use std::fs;
use std::io::{Read, Write};

extern crate chrono;

use chrono::prelude::*;
use chrono::{Utc, DateTime, TimeZone, ParseError};
// Struct to hold the configuration settings
#[derive(Deserialize)]
struct Config {
    database: DatabaseConfig,
    auth: AuthConfig,
    root_zone: RootZoneConfig,
    server: ServerConfig
}

#[derive(Deserialize)]
struct DatabaseConfig {
    location: String,
}

#[derive(Deserialize)]
struct AuthConfig {
    db_location: String,
}

#[derive(Deserialize)]
struct RootZoneConfig {
    location: String,
}

#[ derive(Deserialize)]
struct ServerConfig {
    ip: String,
    port: String,
}

static PERMANENT_RECORDS: [&str; 18] = [
    "ns1",
    "ns2",
    "ns3",
    "root-server",
    "root",
    "nic",
    "admin",
    "support",
    "whois",
    "dns",
    "registry",
    "www",
    "ftp",
    "mail",
    "abuse",
    "security",
    "example",
    "test",
];

#[derive(Deserialize)]
struct CheckQuery {
    name: String, // List separated by commas
}

#[derive(Deserialize, Serialize)]
struct CheckResponse {
    data: Vec<(String, bool)>,
}

#[get("/check")]
async fn check(query: web::Query<CheckQuery>, config: web::Data<Config>) -> impl Responder {
    let conn = connect_db(&config.database.location).unwrap();
    // incoming query is in the format ?name=name1,name2,name3
    // split into vec
    let mut data = Vec::new();
    let names: Vec<&str> = query.name.split(',').collect();

    for name in names.iter() {
        if PERMANENT_RECORDS.contains(&name) {
            data.push((name.to_string(), false));
            continue;
        }
        let mut stmt = conn
            .prepare("SELECT EXISTS(SELECT 1 FROM domains WHERE domainName = ?)")
            .unwrap();
        let exists = !stmt.exists(&[name]).unwrap();
        data.push((name.to_string(), !exists));
    }

    web::Json(CheckResponse { data })
}

#[derive(Serialize)]
struct DomainInfo {
    domainName: String,
    registrant: String,
    registrar: String,
    status: String,
    nameservers: String,
    createdDate: String,
    expiryDate: String,
    lastUpdatedDate: String,
}

impl DomainInfo {
    fn to_string(&self) -> String {
        format!(
            "Domain Name: {}\nRegistrant: {}\nRegistrar: {}\nStatus: {}\nNameservers: {}\nCreated Date: {}\nExpiry Date: {}\nLast Updated Date: {}",
            self.domainName,
            self.registrant,
            self.registrar,
            self.status,
            self.nameservers,
            self.createdDate,
            self.expiryDate,
            self.lastUpdatedDate
        )
    }
}

#[derive(Deserialize)]
struct InfoQuery {
    name: String, // Single name
    auth_name: String,
    auth_key: String,
}

#[get("/info")]
async fn info(
    query: web::Query<InfoQuery>,
    config: web::Data<Config>,
) -> Result<Json<DomainInfo>, Error> {
    let auth = auth_user(&config.auth.db_location, &query.auth_name, &query.auth_key);
    let conn = connect_db(&config.database.location).unwrap();
    let mut stmt = conn
        .prepare("SELECT * FROM domains WHERE domainName = ? and registrar = ?")
        .unwrap();
    let exists = stmt.exists(&[&query.name, &query.auth_name]).unwrap();

    if exists && auth {
        let mut rows = stmt.query(&[&query.name, &query.auth_name]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let domainInfo = DomainInfo {
            domainName: row.get(0).unwrap(),
            registrant: row.get(1).unwrap(),
            registrar: row.get(2).unwrap(),
            status: row.get(3).unwrap(),
            nameservers: row.get(4).unwrap(),
            createdDate: row.get(5).unwrap(),
            expiryDate: row.get(6).unwrap(),
            lastUpdatedDate: row.get(7).unwrap(),
        };
        Ok(web::Json(domainInfo))
    } else {
        Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
    }
}

#[derive(Deserialize)]
struct BigQuery {
    domainName: String,
    registrant: String,
    // registrar: String,
    nameservers: String,
    auth_name: String,
    auth_key: String,
}

// price, not implemented: 1$
#[post("/create")]
async fn create(
    query: web::Json<BigQuery>,
    config: web::Data<Config>,
) -> Result<Json<DomainInfo>, Error> {
    if PERMANENT_RECORDS.contains(&query.domainName.as_str()) {
        return Err(actix_web::error::ErrorBadRequest("Domain name is reserved"));
    }
    let auth = auth_user(&config.auth.db_location, &query.auth_name, &query.auth_key);
    let conn = connect_db(&config.database.location).unwrap();
    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM domains WHERE domainName = ?)")
        .unwrap();
    let exists: bool = stmt.query_row(&[&query.domainName], |row| row.get(0)).unwrap();
    let now = Utc::now();
    let year_from_now = now + chrono::Duration::days(365);
    println!("now: {}", now.to_string());
    if !exists && auth {
        conn.execute(
            "INSERT INTO domains (domainName, registrant, registrar, status, nameservers, createdDate, expiryDate, lastUpdatedDate)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            [
                &query.domainName,
                &query.registrant,
                &query.auth_name,
                "active",
                &query.nameservers,
                // put the unix time number in the database
                

                &now.to_string(),
                &year_from_now.to_string(), 
                &now.to_string(),
            ],
        )
        .unwrap();
        let domainInfo = DomainInfo {
            domainName: query.domainName.clone(),
            registrant: query.registrant.clone(),
            registrar: query.auth_name.clone(),
            status: "active".to_string(),
            nameservers: query.nameservers.clone(),
            createdDate: now.to_string(),
            expiryDate: year_from_now.to_string(),
            lastUpdatedDate: now.to_string(),
        };
        Ok(web::Json(domainInfo))
    } else {
        Err(actix_web::error::ErrorBadRequest("Domain already exists"))
    }
}

#[derive(Deserialize)]
struct SimpleQuery {
    domainName: String,
    auth_name: String,
    auth_key: String,
}

#[delete("/delete")]
async fn delete(
    query: web::Json<SimpleQuery>,
    config: web::Data<Config>,
) -> Result<HttpResponse, Error> {
    let auth = auth_user(&config.auth.db_location, &query.auth_name, &query.auth_key);

    let conn = connect_db(&config.database.location)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM domains WHERE domainName = ? AND registrar = ?)")
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let exists: bool = stmt
        .query_row(params![&query.domainName, &query.auth_name], |row| row.get(0))
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if exists && auth {
        conn.execute("DELETE FROM domains WHERE domainName = ?", params![&query.domainName])
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        Ok(HttpResponse::Ok().finish())
    } else {
        Err(actix_web::error::ErrorBadRequest("Domain does not exist or authentication failed"))
    }
}

// renews a domain by taking the expirt date and adding a year to it
// price, not implemented: 0.5$
#[post("/renew")]
async fn renew(
    query: web::Json<SimpleQuery>,
    config: web::Data<Config>,
) -> Result<HttpResponse, Error> {
    let auth = auth_user(&config.auth.db_location, &query.auth_name, &query.auth_key);

    let conn = connect_db(&config.database.location)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM domains WHERE domainName = ? AND registrar = ?)")
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let exists: bool = stmt
        .query_row(params![&query.domainName, &query.auth_name], |row| row.get(0))
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    if exists && auth {
        let mut stmt = conn
            .prepare("SELECT expiryDate FROM domains WHERE domainName = ? AND registrar = ?")
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        let expiry_date: String = stmt
            .query_row(params![&query.domainName], |row| row.get(0))
            .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        // if the expiry date is in the past then set it to the current date
        let t_expiry_date = expiry_date.parse::<DateTime<Utc>>().unwrap();
        let now = Utc::now();
        let expiry_date: String;
        if t_expiry_date < now {
            expiry_date = now.to_string();
        } else {
            expiry_date = t_expiry_date.to_string();
        } 

        // add a year to expiry date
        let new_expiry_date = expiry_date.parse::<DateTime<Utc>>().unwrap().checked_add_signed(chrono::Duration::days(365)).unwrap(); 
        conn.execute(
            "UPDATE domains SET expiryDate = ? WHERE domainName = ?",
            params![&new_expiry_date.to_string(), &query.domainName],
        )
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        Ok(HttpResponse::Ok().finish())
    } else {
        Err(actix_web::error::ErrorBadRequest("Domain does not exist or authentication failed"))
    }
}


// transfers a domain to another registrar: TODO
/*#[post("/transfer")]*/



// updates the zone file 
#[put("/update")]
async fn update(
    query: web::Json<BigQuery>,
    config: web::Data<Config>,
) -> Result<HttpResponse, Error> {
    let auth = auth_user(&config.auth.db_location, &query.auth_name, &query.auth_key);

    let conn = connect_db(&config.database.location)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM domains WHERE domainName = ? AND registrar = ?)")
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    let exists: bool = stmt
        .query_row(params![&query.domainName, &query.auth_name], |row| row.get(0))
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;

    if exists && auth {
        conn.execute(
            "UPDATE domains SET nameservers = ?, registrant = ? WHERE domainName = ? AND registrar = ?",
            params![&query.nameservers, &query.registrant, &query.domainName, &query.auth_name],
        )
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
        Ok(HttpResponse::Ok().finish())
    } else {
        Err(actix_web::error::ErrorBadRequest("Domain does not exist or authentication failed"))
    }
}



fn write_to_zone_file(path: &str, config: &Config) {
    let conn = connect_db(&config.database.location).unwrap();
    let mut stmt = conn
        .prepare("SELECT domainName, nameservers FROM domains")
        .unwrap();
    let rows = stmt.query_map([], |row| row.get(0)).unwrap();
    let zone_file_path = &path;
    println!( "zone file path: {}", zone_file_path);
    let mut zone_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(zone_file_path)
        .unwrap();
    zone_file.write_all(b";netw.\n").unwrap();
    for row in rows {
        let domain_name: String = row.unwrap();
        let mut stmt = conn
            .prepare("SELECT nameservers FROM domains WHERE domainName = ?")
            .unwrap();
        let nameservers: String = stmt.query_row(&[&domain_name], |row| row.get(0)).unwrap();
        let mut nameservers: Vec<&str> = nameservers.split(',').collect();
        // zone_file.write_all(format!("{} IN NS {}\n", domain_name, nameservers[0]).as_bytes()).unwrap();
        if nameservers.len() > 1 {
            if nameservers.len() > 2 {
                nameservers = Vec::from(&nameservers[1..2]) 
            }
            for ns in nameservers.iter() {
                zone_file.write_all(format!("{}.netw. IN NS {}.\n", domain_name, ns).as_bytes()).unwrap();
            }
        }
    }

}

fn auth_user(db_path: &str, name: &str, key: &str) -> bool {
    let conn = connect_db(db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT EXISTS(SELECT 1 FROM users WHERE name = ? AND key = ?)")
        .unwrap();
    // if the answer is 1, then true, if it is 0 then false
    let exists = stmt.query_row(&[name, key], |row| row.get(0)).unwrap();
    exists
}

// Helper function to load the configuration file
fn load_config() -> Config {
    let config_path = env::current_dir().unwrap().join("config.toml");
    let config = std::fs::read_to_string(config_path).expect("Failed to read config file");
    toml::from_str(&config).unwrap()
}

// Helper function to connect to a SQLite database
fn connect_db(db_path: &str) -> Result<Connection> {
    Connection::open(db_path)
}

fn create_file_if_not_exist(path: &str) {
    if !std::path::Path::new(path).exists() {
        // create dir to that file
        fs::create_dir_all(std::path::Path::new(path).parent().unwrap())
            .expect("Failed to create directory");
        fs::File::create(path).expect("Failed to create file");
    }
}

fn create_auth_tables(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            key TEXT NOT NULL
        )",
        [],
    )?; /*
        conn.execute(
            "INSERT INTO users (name, key) VALUES ('NET_Domains', 'password');",
            [],
        )?;*/
    Ok(())
}

fn create_data_tables(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS domains (
            domainName TEXT PRIMARY KEY,
            registrant TEXT,
            registrar TEXT,
            status TEXT,
            nameservers TEXT,
            createdDate TEXT,
            expiryDate TEXT,
            lastUpdatedDate TEXT
        );",
        [],
    )?; /*
        conn.execute(
                "INSERT INTO domains (domainName, registrant, registrar, status, nameservers, createdDate, expiryDate, lastUpdatedDate)
                VALUES ('example', 'John Doe', 'NET_Domains', 'active', 'ns1.example,ns2.example', '2021-01-01', '2022-01-01', '2021-01-01');",
                [],
            )?;*/
    Ok(())
}

fn create_databases(config: web::Data<Config>) {
    create_file_if_not_exist(&config.database.location);
    create_file_if_not_exist(&config.auth.db_location);
    let auth_conn = connect_db(&config.auth.db_location).unwrap();
    let data_conn = connect_db(&config.database.location).unwrap();

    create_auth_tables(&auth_conn).unwrap();
    create_data_tables(&data_conn).unwrap();
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = web::Data::new(load_config());
    create_databases(config.clone());
    write_to_zone_file(&config.root_zone.location, &config.get_ref());
    let c2 = config.clone();
    let ip = &c2.server.ip;
    let port = &c2.server.port;


    HttpServer::new(move || {
        App::new()
            .app_data(config.clone())
            .service(check)
            .service(info)
            .service(create)
            .service(delete)
            .service(renew)
            // .service(transfer)
            .service(update)
    })
    .bind(format!("{}:{}", ip, port))?
    .run()
    .await
}
