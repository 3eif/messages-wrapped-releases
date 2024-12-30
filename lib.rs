#![warn(clippy::all)]

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};
use std::{env, fs, io};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use brotli::enc::writer::CompressorWriter;
use brotli::enc::BrotliEncoderParams;
use connection::{
	get_address_book_db_connections, get_chat_db_connection, init_sqlite, shutdown_sqlite
};
use contacts::{Contact, Contacts};
use from_query::QueryAll;
use handles::Handles;
use hex;
use imessage_database::error::table::TableError;
use imessage_database::tables::messages::Message;
use jemallocator::Jemalloc;
use napi_derive::napi;
use prost::Message as ProstMessage;
use rand::Rng;
use sha2::{Digest, Sha256};
use stats::stats::YearsStats;
use thiserror::Error;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod connection;
mod contacts;
mod extensions;
mod from_query;
mod handles;
mod message;
mod stats;

#[derive(Error, Debug)]
pub enum AnalyzerError {
	#[error("imessage table error {0}")]
	Table(TableError),

	#[error(transparent)]
	Io(#[from] io::Error),

	#[error(transparent)]
	Sql(#[from] rusqlite::Error),

	#[error(transparent)]
	Image(#[from] image::ImageError)
}

impl From<TableError> for AnalyzerError {
	fn from(value: TableError) -> Self {
		Self::Table(value)
	}
}

pub type AnalyzerResult<T> = Result<T, AnalyzerError>;

#[derive(Debug, Copy, Clone)]
pub struct AnalysisTiming {
	chat_db_time: Duration,
	messages_query_time: Duration,
	contacts_time: Duration,
	handles_time: Duration,
	total_time: Duration
}

#[derive(Debug)]
struct StatsGenerationTiming {
	year_time: Duration,
	month_time: Duration,
	weekday_time: Duration,
	hour_time: Duration,
	top_sent_time: Duration,
	words_emoji_time: Duration,
	messages_per_day_time: Duration,
	message_length_time: Duration,
	reactions_time: Duration,
	response_time: Duration,
	chat_stats_time: Duration,
	left_on_read_time: Duration,
	slurs_time: Duration,
	reactionner_time: Duration,
	favor_time: Duration,
	freaky_time: Duration,
	double_text_time: Duration,
	session_time: Duration,
	group_chat_slurs_time: Duration,
	send_received_ratio_time: Duration,
	realest_time: Duration,
	total_time: Duration,
	dirty_mouth_time: Duration,
	degenerate_time: Duration,
}

pub fn gather_imessage_data<P>(
	path: P, address_book_path: P
) -> AnalyzerResult<(Vec<Message>, Contacts, Handles, AnalysisTiming)>
where
	P: AsRef<Path>
{
	let total_start = Instant::now();

	let chat_db = get_chat_db_connection(path)?;
	let chat_db_time = total_start.elapsed();

	let messages_start = Instant::now();
	let mut messages = Message::query_all(&chat_db, [])?;
	messages.sort_by_key(|m| m.date);
	let messages_query_time = messages_start.elapsed();

	let contacts_start = Instant::now();
	let address_book_dbs = get_address_book_db_connections(address_book_path.as_ref())?;
	let contacts = Contacts::new(&address_book_dbs, address_book_path.as_ref())?;
	for conn in address_book_dbs {
		let _ = conn.close();
	}
	let contacts_time = contacts_start.elapsed();

	let handles_start = Instant::now();
	let handles = Handles::new(&chat_db)?;
	let handles_time = handles_start.elapsed();

	let _ = chat_db.close();

	Ok((
		messages,
		contacts,
		handles,
		AnalysisTiming {
			chat_db_time,
			messages_query_time,
			contacts_time,
			handles_time,
			total_time: total_start.elapsed()
		}
	))
}

fn encrypt_data(data: &[u8]) -> AnalyzerResult<(Vec<u8>, Vec<u8>)> {
	let mut compressed = Vec::new();
	{
		let params = BrotliEncoderParams { quality: 11, lgwin: 22, ..Default::default() };

		let mut compressor = CompressorWriter::with_params(
			&mut compressed,
			4096, // buffer size
			&params
		);

		compressor.write_all(data)?;
		compressor.flush()?;
		// Ensure all data is written
		drop(compressor);
	}

	println!(
		"Rust encryption - Original size: {}, Compressed size: {}",
		data.len(),
		compressed.len()
	);

	// Generate random key
	let mut rng = rand::thread_rng();
	let mut key_bytes = [0u8; 32];
	rng.fill(&mut key_bytes);

	let cipher = Aes256Gcm::new_from_slice(&key_bytes)
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

	// Use fixed IV of all zeros
	let iv = Nonce::from_slice(&[0u8; 12]);
	let encrypted = cipher
		.encrypt(iv, compressed.as_ref())
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

	println!(
		"Rust encryption - Key length: {}, Encrypted size: {}, Key bytes: {:?}",
		key_bytes.len(),
		encrypted.len(),
		&key_bytes
	);

	println!(
		"Rust encryption - First 32 bytes of encrypted data: {:?}",
		&encrypted[..32.min(encrypted.len())]
	);

	Ok((key_bytes.to_vec(), encrypted))
}

pub async fn send_stats(
	stats: &YearsStats, api_url: Option<String>
) -> AnalyzerResult<(String, String, Duration, Duration)> {
	let base_url = api_url.unwrap_or_else(|| String::from("https://messageswrapped.com"));
	let upload_url = format!("{}/api/upload", base_url);

	let db_path = Path::new(&env::var("HOME").unwrap()).join("Library/Messages/chat.db");
	let chat_db = get_chat_db_connection(&db_path)?;

	// let phone_number = chat_db
	// 	.prepare(
	// 		"SELECT account FROM message WHERE service = 'SMS' AND account LIKE 'P:+%'
	// LIMIT 1" 	)?
	// 	.query_row([], |row| row.get::<_, String>(0))
	// 	.ok()
	// 	.and_then(|account| account.strip_prefix("P:").map(String::from))
	// 	.unwrap_or_default();

	// println!("Found user's phone number from messages: {}", phone_number);

	// let clean_number = phone_number
	// 	.chars()
	// 	.filter(char::is_ascii_digit)
	// 	.collect::<String>();

	// let mut hasher = Sha256::new();
	// hasher.update(format!("{}{}", clean_number,
	// "MRgUPTuRLRbqL6DJ9pdA").as_bytes()); let hashed_phone =
	// hex::encode(&hasher.finalize()[..8]); print!("Rust - Final hash: {}",
	// hashed_phone);

	let stats_bytes = stats.encode_to_vec();

	let encryption_start = Instant::now();
	let original_size = stats_bytes.len();
	let (key, encrypted_data) = encrypt_data(&stats_bytes)?;
	println!(
		"Original size: {}, Compressed + Encrypted size: {}, Reduction: {:.1}%",
		original_size,
		encrypted_data.len(),
		(1.0 - (encrypted_data.len() as f64 / original_size as f64)) * 100.0
	);
	let encryption_time = encryption_start.elapsed();

	let upload_start = Instant::now();

	let client = reqwest::Client::new();
	println!("Encrypted data size: {}", encrypted_data.len());
	let response = client
		.post(&upload_url)
		.timeout(Duration::from_secs(30))
		.header("Content-Type", "application/octet-stream")
		.body(encrypted_data)
		.send()
		.await
		.map_err(|e| {
			let error_msg = if e.is_timeout() {
				format!("Request timed out while uploading to {}", upload_url)
			} else if e.is_connect() {
				format!(
					"Failed to connect to {}. Please check your internet connection",
					upload_url
				)
			} else {
				format!("Upload failed: {} (URL: {})", e, upload_url)
			};
			io::Error::new(io::ErrorKind::Other, error_msg)
		})?;

	if !response.status().is_success() {
		let status = response.status();
		let error_body = response.text().await.unwrap_or_default();
		return Err(io::Error::new(
			io::ErrorKind::Other,
			format!(
				"Upload failed with status {}: {}. Server response: {}",
				status,
				status.canonical_reason().unwrap_or("Unknown error"),
				if error_body.is_empty() {
					"No error details provided"
				} else {
					&error_body
				}
			)
		)
		.into());
	}

	let response_data: serde_json::Value = response
		.json()
		.await
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

	let key_base64 = URL_SAFE.encode(key);
	let share_url = format!(
		"{}/s/{}#{}",
		base_url,
		response_data["id"].as_str().unwrap_or_default(),
		key_base64,
		// &hashed_phone[..16] // Use first 16 chars of hash
	);

	let upload_time = upload_start.elapsed();

	Ok((share_url, key_base64, encryption_time, upload_time))
}

#[napi]
pub async fn fetch_stats(api_url: String) -> napi::Result<String> {
	let api_url_clone = api_url.clone();
	let total_start = SystemTime::now();

	// Create a guard that ensures SQLite is properly shut down
	let _guard = scopeguard::guard((), |()| shutdown_sqlite());

	let sqlite_start = Instant::now();
	init_sqlite();
	let sqlite_init_time = sqlite_start.elapsed();

	let db_path = Path::new(&env::var("HOME").unwrap()).join("Library/Messages/chat.db");

	let address_book_path =
		Path::new(&env::var("HOME").unwrap()).join("Library/Application Support/AddressBook");

	let analysis_start = Instant::now();
	let result = match gather_imessage_data(&db_path, &address_book_path) {
		Ok((messages, contacts, handles, timing)) => {
			let analysis_time = analysis_start.elapsed();

			let stats_start = Instant::now();
			let (year_stats, stats_timing) =
				stats::get_all_yearly_stats(&messages, &contacts, &handles);
			let stats_time = stats_start.elapsed();

			// Drop large data structures
			drop(messages);
			drop(contacts);
			drop(handles);

			match send_stats(&year_stats, Some(api_url)).await {
				Ok((share_url, encryption_key, encryption_time, upload_time)) => {
					let timing_info = format!(
						"\
						=== System Info ===\nChat.db Size: {:.2} MB\n\n=== Initial Setup ===\nSQLite Init: \
						 {:?}\n\n=== Gather iMessage Data Phase ===\nDB Connection: \
						 {:?}\nMessages Query: {:?}\nContacts Load: {:?}\nHandles Load: \
						 {:?}\nTotal Analysis Time: {:?}\nTotal Gather iMessage Data Time: \
						 {:?}\n\n=== Stats Generation Phase ===\nBy Year: {:?}\nBy Month: \
						 {:?}\nBy Weekday: {:?}\nBy Hour: {:?}\nTop Sent Texts: {:?}\nWords and \
						 Emojis: {:?}\nMessages Per Day: {:?}\nMessage Length: {:?}\nMost \
						 Reactions: {:?}\nResponse Time: {:?}\nChat Stats: {:?}\nLeft on Read: \
						 {:?}\nSlurs: {:?}\nReactionner Time: {:?}\nFavor Time: {:?}\nFreaky \
						 Time: {:?}\nDouble Text Time: {:?}\nLongest Texting Sessions: \
						 {:?}\nGroup Chat Slurs: {:?}\nSend/Received Ratio: {:?}\nRealest Friend: \
						 {:?}\nTotal Stats Generation: {:?}\n\n=== Final Phase ===\nEncryption \
						 Time: {:?}\nUpload Time: {:?}\nTotal Encryption & Upload Time: \
						 {:?}\n\n=== Total Time Breakdown ===\nSQLite Init: {:?}\nGather iMessage \
						 Data: {:?}\nStats Generation: {:?}\nEncryption: {:?}\nUpload: {:?}\nSum \
						 of All Phases: {:?}\nTotal Time: {:?}\nDirty Mouth: {:?}\nDegenerate Phrases: \
						 {:?}",
						get_chat_db_size()? as f64,
						sqlite_init_time,
						timing.chat_db_time,
						timing.messages_query_time,
						timing.contacts_time,
						timing.handles_time,
						timing.total_time,
						analysis_time,
						stats_timing.year_time,
						stats_timing.month_time,
						stats_timing.weekday_time,
						stats_timing.hour_time,
						stats_timing.top_sent_time,
						stats_timing.words_emoji_time,
						stats_timing.messages_per_day_time,
						stats_timing.message_length_time,
						stats_timing.reactions_time,
						stats_timing.response_time,
						stats_timing.chat_stats_time,
						stats_timing.left_on_read_time,
						stats_timing.slurs_time,
						stats_timing.reactionner_time,
						stats_timing.favor_time,
						stats_timing.freaky_time,
						stats_timing.double_text_time,
						stats_timing.session_time,
						stats_timing.group_chat_slurs_time,
						stats_timing.send_received_ratio_time,
						stats_timing.realest_time,
						stats_time,
						encryption_time,
						upload_time,
						upload_time + encryption_time,
						sqlite_init_time,
						analysis_time,
						stats_time,
						encryption_time,
						upload_time,
						sqlite_init_time +
							analysis_time + stats_time +
							encryption_time + upload_time,
						total_start.elapsed().unwrap_or_default(),
						stats_timing.dirty_mouth_time,
						stats_timing.degenerate_time
					);

					serde_json::json!({
						"success": true,
						"data": {
							"shareUrl": share_url,
							"encryptionKey": encryption_key,
						},
						"timing": timing_info
					})
					.to_string()
				}
				Err(e) => {
					eprintln!("Upload error details: {:?}", e);

					serde_json::json!({
						"success": false,
						"error": {
							"message": format!("Failed to generate your Messages Wrapped: {}", e),
							"url": api_url_clone,
							"details": {
								"timestamp": SystemTime::now()
									.duration_since(SystemTime::UNIX_EPOCH)
									.unwrap_or_default()
									.as_secs(),
								"errorType": "upload_failed",
								"fullError": format!("{:?}", e)
							}
						}
					})
					.to_string()
				}
			}
		}
		Err(err) => {
			eprintln!("Analysis error details: {:?}", err);
			serde_json::json!({
				"success": false,
				"error": {
					"message": format!("Failed to analyze messages: {}", err),
					"details": {
						"timestamp": SystemTime::now()
							.duration_since(SystemTime::UNIX_EPOCH)
							.unwrap_or_default()
							.as_secs(),
						"errorType": "analysis_failed",
						"fullError": format!("{:?}", err)
					}
				}
			})
			.to_string()
		}
	};

	Ok(result)
}

#[napi]
pub fn get_chat_db_size() -> napi::Result<f64> {
	let db_path = Path::new(&env::var("HOME").unwrap()).join("Library/Messages/chat.db");

	let file_size_mb = fs::metadata(&db_path)
		.map(|metadata| (metadata.len() as f64 / 1_048_576.0))
		.unwrap_or(0.0);

	Ok(file_size_mb)
}

#[napi]
pub fn has_contacts() -> napi::Result<bool> {
	let address_book_path =
		Path::new(&env::var("HOME").unwrap()).join("Library/Application Support/AddressBook");

	match get_address_book_db_connections(&address_book_path) {
		Ok(connections) => {
			let has_contacts = connections.iter().any(|conn| {
				Contact::query_all(conn, [])
					.map(|contacts| !contacts.is_empty())
					.unwrap_or(false)
			});
			Ok(has_contacts)
		}
		Err(_) => Ok(false)
	}
}
