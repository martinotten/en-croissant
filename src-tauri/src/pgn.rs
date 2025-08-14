use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use crate::{error::Error, AppState};
use std::path::Path;
use std::sync::{Arc, Mutex};

const GAME_OFFSET_FREQ: usize = 100;

struct PgnParser {
    reader: BufReader<File>,
    line: String,
    game: String,
    start: u64,
}

impl PgnParser {
    fn new(file: File) -> io::Result<Self> {
        let mut reader = BufReader::new(file);
        let start = ignore_bom(&mut reader)?;
        Ok(Self {
            reader,
            line: String::new(),
            game: String::new(),
            start,
        })
    }

    fn position(&mut self) -> io::Result<u64> {
        self.reader.stream_position()
    }

    fn offset_by_index(&mut self, n: usize, state: &AppState, file: &str) -> io::Result<()> {
        let offset_index = n / GAME_OFFSET_FREQ;
        let n_left = n % GAME_OFFSET_FREQ;
        // Look up precomputed offsets for this file, if available. The offsets map
        // is keyed by the canonicalized file path string. If offsets are missing
        // or the requested index is out of range, fall back to scanning from the
        // file start which is slower but safe.
        if let Some(pgn_offsets) = state.pgn_offsets.get(file) {
            if offset_index == 0 || offset_index <= pgn_offsets.len() {
                let offset = if offset_index == 0 {
                    self.start
                } else {
                    pgn_offsets[offset_index - 1]
                };

                self.reader.seek(SeekFrom::Start(offset))?;
                self.skip_games(n_left)?;
            } else {
                self.reader.seek(SeekFrom::Start(self.start))?;
                self.skip_games(n)?;
            }
        } else {
            self.reader.seek(SeekFrom::Start(self.start))?;
            self.skip_games(n)?;
        }

        Ok(())
    }

    /// Skip n games, and return the number of bytes read
    fn skip_games(&mut self, n: usize) -> io::Result<usize> {
        let mut new_game = false;
        let mut skipped = 0;
        let mut count = 0;

        if n == 0 {
            return Ok(0);
        }

        let mut line = String::new();
        loop {
            let bytes = self.reader.read_line(&mut line)?;
            skipped += bytes;
            if bytes == 0 {
                break;
            }
            if line.starts_with('[') {
                if new_game {
                    count += 1;
                    if count == n {
                        self.reader.seek(SeekFrom::Current(-(bytes as i64)))?;
                        break;
                    }
                    new_game = false;
                }
            } else {
                new_game = true;
            }
            line.clear();
        }
        Ok(skipped)
    }

    fn read_game(&mut self) -> io::Result<String> {
        let mut new_game = false;
        self.game.clear();
        loop {
            let bytes = self.reader.read_line(&mut self.line)?;
            if bytes == 0 {
                break;
            }
            if self.line.starts_with('[') {
                if new_game {
                    break;
                }
            } else {
                new_game = true;
            }
            self.game.push_str(&self.line);
            self.line.clear();
        }
        Ok(self.game.clone())
    }
}

fn ignore_bom(reader: &mut BufReader<File>) -> io::Result<u64> {
    let mut bom = [0; 3];
    let n = reader.read(&mut bom)?;
    if n < 3 || bom != [0xEF, 0xBB, 0xBF] {
        reader.seek(SeekFrom::Start(0))?;
        return Ok(0);
    }
    Ok(3)
}

fn file_to_key(path: &Path) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

#[tauri::command]
#[specta::specta]
pub async fn count_pgn_games(
    file: PathBuf,
    state: tauri::State<'_, AppState>,
) -> Result<i32, Error> {
    let files_string = file_to_key(&file);

    let file = File::open(&file)?;

    let mut parser = PgnParser::new(file.try_clone()?)?;

    let mut offsets = Vec::new();

    let mut count = 0;

    while let Ok(skipped) = parser.skip_games(1) {
        if skipped == 0 {
            break;
        }
        count += 1;
        if count % GAME_OFFSET_FREQ as i32 == 0 {
            let cur_pos = parser.position()?;
            offsets.push(cur_pos);
        }
    }

    state.pgn_offsets.insert(files_string, offsets);
    Ok(count)
}

#[tauri::command]
#[specta::specta]
pub async fn read_games(
    file: PathBuf,
    start: i32,
    end: i32,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, Error> {
    let file_r = File::open(&file)?;

    let mut parser = PgnParser::new(file_r.try_clone()?)?;
    let files_string = file_to_key(&file);
    parser.offset_by_index(start as usize, &state, &files_string)?;

    let mut games: Vec<String> = Vec::with_capacity((end - start) as usize);

    for _ in start..=end {
        let game = parser.read_game()?;
        if game.is_empty() {
            break;
        }
        games.push(game);
    }
    Ok(games)
}

#[tauri::command]
#[specta::specta]
pub async fn delete_game(
    file: PathBuf,
    n: i32,
    state: tauri::State<'_, AppState>,
) -> Result<(), Error> {
    let file_r = File::open(&file)?;

    let mut parser = PgnParser::new(file_r.try_clone()?)?;
    let files_string = file_to_key(&file);
    parser.offset_by_index(n as usize, &state, &files_string)?;

    // Acquire per-file lock to serialize modifications to this PGN file.
    let lock_arc: Arc<Mutex<()>> = match state.pgn_locks.get(&files_string) {
        Some(v) => v.clone(),
        None => {
            let a = Arc::new(Mutex::new(()));
            state.pgn_locks.insert(files_string.clone(), a.clone());
            a
        }
    };
    let _guard = lock_arc.lock().unwrap();

    let starting_bytes = parser.position()?;

    parser.skip_games(1)?;

    let mut file_w = OpenOptions::new().write(true).open(file)?;

    file_w.seek(SeekFrom::Start(starting_bytes))?;

    write_to_end(&mut parser.reader, &mut file_w)?;
    Ok(())
}

fn write_to_end<R: Read>(reader: &mut R, writer: &mut File) -> io::Result<()> {
    io::copy(reader, writer)?;
    let end = writer.stream_position()?;
    writer.set_len(end)?;
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub async fn write_game(
    file: PathBuf,
    n: i32,
    pgn: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), Error> {
    if !file.exists() {
        File::create(&file)?;
    }

    let file_r = File::open(&file)?;
    let mut file_w = OpenOptions::new().write(true).open(&file)?;

    let mut tmpf = tempfile::tempfile()?;
    io::copy(&mut file_r.try_clone()?, &mut tmpf)?;

    let mut parser = PgnParser::new(file_r.try_clone()?)?;
    let files_string = file_to_key(&file);
    parser.offset_by_index(n as usize, &state, &files_string)?;

    // Acquire per-file lock to serialize modifications to this PGN file.
    let lock_arc: Arc<Mutex<()>> = match state.pgn_locks.get(&files_string) {
        Some(v) => v.clone(),
        None => {
            let a = Arc::new(Mutex::new(()));
            state.pgn_locks.insert(files_string.clone(), a.clone());
            a
        }
    };
    let _guard = lock_arc.lock().unwrap();

    tmpf.seek(SeekFrom::Start(parser.position()?))?;
    tmpf.write_all(pgn.as_bytes())?;

    parser.skip_games(1)?;

    write_to_end(&mut parser.reader, &mut tmpf)?;

    tmpf.seek(SeekFrom::Start(0))?;

    write_to_end(&mut tmpf, &mut file_w)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn file_to_key_canonicalizes_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.pgn");
        File::create(&file).unwrap();

        let key = file_to_key(&file);
        let canon = std::fs::canonicalize(&file).unwrap().to_string_lossy().to_string();
        assert_eq!(key, canon);
    }

    #[test]
    fn file_to_key_falls_back_on_missing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("missing.pgn");
        if file.exists() {
            std::fs::remove_file(&file).unwrap();
        }

        let key = file_to_key(&file);
        assert_eq!(key, file.to_string_lossy().to_string());
    }

    #[test]
    fn precomputed_offsets_seek() -> std::io::Result<()> {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("many.pgn");
        let mut f = File::create(&file)?;

        // Create 150 small games
        for i in 0..150 {
            writeln!(f, "[Event \"Game {}\"]", i)?;
            writeln!(f, "\n1. e4 e5 2. Nf3 Nc6\n")?;
        }
        f.flush()?;

        // compute offset after 100 games using a dedicated parser
        let mut parser_off = PgnParser::new(File::open(&file)?)?;
        parser_off.skip_games(100)?;
        let offset = parser_off.position()?;

        let key = file_to_key(&file);
        // Construct a minimal AppState without calling Default to avoid side-effects
        // (AuthState::default binds to a socket). Initialize only the fields we
        // need for this test.
        use dashmap::DashMap;
        use std::net::SocketAddr;
        use oauth2::basic::BasicClient;
        use oauth2::{ClientId, AuthUrl, TokenUrl, RedirectUrl, PkceCodeChallenge, PkceCodeVerifier, CsrfToken};
        use std::sync::Arc;

        let connection_pool: DashMap<String, diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::SqliteConnection>>> = DashMap::new();
        let line_cache: DashMap<(crate::db::GameQueryJs, std::path::PathBuf), (Vec<crate::db::PositionStats>, Vec<crate::db::NormalizedGame>)> = DashMap::new();
        let db_cache = std::sync::Mutex::new(Vec::new());
        let new_request = Arc::new(tokio::sync::Semaphore::new(2));
        let pgn_offsets = DashMap::new();
        let fide_players = tokio::sync::RwLock::new(Vec::new());
        let engine_processes = DashMap::new();
        let pgn_locks = DashMap::new();

        // Minimal AuthState-like value without binding sockets
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let client = BasicClient::new(
            ClientId::new("org.encroissant.app".to_string()),
            None,
            AuthUrl::new("https://example.com/".to_string()).unwrap(),
            TokenUrl::new("https://example.com/token".to_string()).ok(),
        )
        .set_redirect_uri(RedirectUrl::new("http://127.0.0.1:0/callback".to_string()).unwrap());

        let auth = crate::oauth::AuthState {
            csrf_token: CsrfToken::new_random(),
            pkce: Arc::new((pkce_challenge, PkceCodeVerifier::secret(&pkce_verifier).to_string())),
            client: Arc::new(client),
            socket_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        };

        let state = crate::AppState {
            connection_pool,
            line_cache,
            db_cache,
            new_request,
            pgn_offsets,
            pgn_locks,
            fide_players,
            engine_processes,
            auth,
        };

        state.pgn_offsets.insert(key.clone(), vec![offset]);

        // test offset_by_index positions parser at the precomputed offset
        let mut parser = PgnParser::new(File::open(&file)?)?;
        parser.offset_by_index(100, &state, &key)?;
        let pos = parser.position()?;
        assert_eq!(pos, offset);

        // index 101 should be positioned after that offset
        parser.offset_by_index(101, &state, &key)?;
        let pos2 = parser.position()?;
        assert!(pos2 > offset);

        Ok(())
    }
}
