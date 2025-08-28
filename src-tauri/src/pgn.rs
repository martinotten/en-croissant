use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use crate::{error::Error, AppState};
use fs2::FileExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

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

    fn offset_by_index(
        &mut self,
        n: usize,
        pgn_offsets: &dashmap::DashMap<String, Vec<u64>>,
        pgn_meta: &dashmap::DashMap<String, (u64, u64)>,
        file: &str,
    ) -> io::Result<()> {
        let offset_index = n / GAME_OFFSET_FREQ;
        let n_left = n % GAME_OFFSET_FREQ;

        // Helper to seek to start and skip `n` games
        let fallback = |parser: &mut Self| -> io::Result<()> {
            parser.reader.seek(SeekFrom::Start(parser.start))?;
            parser.skip_games(n)?;
            Ok(())
        };

        // Try to use pre‑computed offsets if they are still valid
        if let Some(offsets) = pgn_offsets.get(file) {
            let offsets = offsets.value();

            // Verify file metadata matches cached metadata
            let meta_valid = if let Some(cached_meta) = pgn_meta.get(file) {
                if let Ok(current_meta) = get_file_meta(Path::new(file)) {
                    *cached_meta == current_meta
                } else {
                    false
                }
            } else {
                false
            };

            if meta_valid && (offset_index == 0 || offset_index <= offsets.len()) {
                // Determine the byte offset to seek to
                let target = if offset_index == 0 {
                    self.start
                } else {
                    offsets[offset_index - 1]
                };
                self.reader.seek(SeekFrom::Start(target))?;
                self.skip_games(n_left)?;
                return Ok(());
            }
        }

        // Fallback: no valid offsets → scan from start
        fallback(self)
    }
    /// Skip `n` games and return the total number of bytes consumed.
    fn skip_games(&mut self, n: usize) -> io::Result<usize> {
        if n == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0usize;
        let mut games_skipped = 0usize;
        let mut inside_game = false;

        while games_skipped < n {
            let line_bytes = self.reader.read_line(&mut self.line)?;
            if line_bytes == 0 {
                // EOF reached
                break;
            }
            bytes_read += line_bytes;

            // Find first non‑whitespace byte
            let first_char = self
                .line
                .as_bytes()
                .iter()
                .skip_while(|b| b.is_ascii_whitespace())
                .next()
                .copied();

            match first_char {
                Some(b'[') => {
                    if inside_game {
                        games_skipped += 1;
                        if games_skipped == n {
                            // Backtrack to the start of this tag line
                            self.reader.seek(SeekFrom::Current(-(line_bytes as i64)))?;
                            break;
                        }
                        inside_game = false;
                    }
                }
                Some(_) => {
                    inside_game = true;
                }
                None => {} // empty line – ignore
            }

            self.line.clear();
        }

        Ok(bytes_read)
    }

    fn read_game(&mut self) -> io::Result<String> {
        let mut new_game = false;
        self.game.clear();
        loop {
            let bytes = self.reader.read_line(&mut self.line)?;
            if bytes == 0 {
                break;
            }
            if self.line.trim_start().starts_with('[') {
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

fn get_file_meta(path: &Path) -> io::Result<(u64, u64)> {
    let md = std::fs::metadata(path)?;
    let modified = md
        .modified()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("modified error: {}", e)))?
        .duration_since(UNIX_EPOCH)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("systemtime error: {}", e)))?
        .as_secs();
    let len = md.len();
    Ok((modified, len))
}
#[tauri::command]
#[specta::specta]
pub async fn count_pgn_games(
    file: PathBuf,
    state: tauri::State<'_, AppState>,
) -> Result<i32, Error> {
    let files_string = file_to_key(&file);
    let path = file.clone();

    let file_handle = File::open(&path)?;

    let mut parser = PgnParser::new(file_handle.try_clone()?)?;

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

    state.pgn_offsets.insert(files_string.clone(), offsets);
    if let Ok(meta) = get_file_meta(&path) {
        state.pgn_index_meta.insert(files_string, meta);
    }
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
    parser.offset_by_index(
        start as usize,
        &state.pgn_offsets,
        &state.pgn_index_meta,
        &files_string,
    )?;

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
    let _file_r = File::open(&file)?;

    // For modifications we perform the work in a blocking task to avoid
    // blocking the async runtime. Clone the small pieces we need from the
    // shared state so they can be moved into the blocking closure.
    let pgn_offsets = state.pgn_offsets.clone();
    let pgn_meta = state.pgn_index_meta.clone();
    let pgn_locks = state.pgn_locks.clone();
    let file_clone = file.clone();

    tokio::task::spawn_blocking(move || -> Result<(), Error> {
        atomic_replace(
            &file_clone,
            n as usize,
            &pgn_offsets,
            &pgn_meta,
            &pgn_locks,
            |parser, tmp| {
                // parser is positioned at the requested index; skip the game to remove
                parser.skip_games(1)?;
                // parser.reader is positioned after the skipped game; copy the rest
                write_to_end(&mut parser.reader, tmp.as_file_mut())?;
                Ok(())
            },
        )
    })
    .await
    .map_err(|e| {
        Error::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("join error: {}", e),
        ))
    })??;

    Ok(())
}

fn write_to_end<R: Read>(reader: &mut R, writer: &mut File) -> io::Result<()> {
    io::copy(reader, writer)?;
    let end = writer.stream_position()?;
    writer.set_len(end)?;
    Ok(())
}

// Helper to centralize the pattern of acquiring the in-process lock,
// taking an exclusive OS lock on the target file, writing to a temporary
// file in the same directory, syncing, and atomically replacing the
// original file. The closure `op` is responsible for writing the desired
// contents into the provided temp file using the positioned `PgnParser`.
fn atomic_replace<F>(
    file_clone: &Path,
    index: usize,
    pgn_offsets: &dashmap::DashMap<String, Vec<u64>>,
    pgn_meta: &dashmap::DashMap<String, (u64, u64)>,
    pgn_locks: &dashmap::DashMap<String, Arc<Mutex<()>>>,
    op: F,
) -> Result<(), Error>
where
    F: FnOnce(&mut PgnParser, &mut tempfile::NamedTempFile) -> io::Result<()>,
{
    // open and position parser
    let mut parser = PgnParser::new(File::open(&file_clone)?)?;
    parser.offset_by_index(index, pgn_offsets, pgn_meta, &file_to_key(&file_clone))?;

    let files_string = file_to_key(&file_clone);

    // Acquire an in-process lock object (Arc<Mutex<()>>) and then lock it
    // so the guard is held while we perform OS-level locking and file
    // replacement.
    let lock_arc: Arc<Mutex<()>> = match pgn_locks.get(&files_string) {
        Some(v) => v.clone(),
        None => {
            let a = Arc::new(Mutex::new(()));
            pgn_locks.insert(files_string.clone(), a.clone());
            a
        }
    };
    let _guard = lock_arc
        .lock()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "mutex poisoned"))?;

    // Open original and acquire exclusive OS-level lock. Wrap the file
    // handle in a small RAII type so we always attempt to unlock when the
    // guard is dropped (covers early returns on errors).
    struct UnlockOnDrop(File);
    impl Drop for UnlockOnDrop {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }

    let orig = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_clone)?;
    orig.lock_exclusive()?;
    let orig_guard = UnlockOnDrop(orig);

    let dir = file_clone.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;

    // Call the provided closure to populate tmp using parser state.
    op(&mut parser, &mut tmp)?;

    // Ensure temp file data is flushed before rename
    tmp.as_file_mut().sync_all()?;

    tmp.persist(&file_clone)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("persist error: {}", e)))?;

    // explicitly drop the guard to unlock before returning
    drop(orig_guard);

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

    // perform the write in a blocking task
    let pgn_offsets = state.pgn_offsets.clone();
    let pgn_meta = state.pgn_index_meta.clone();
    let pgn_locks = state.pgn_locks.clone();
    let file_clone = file.clone();
    let pgn_clone = pgn.clone();

    tokio::task::spawn_blocking(move || -> Result<(), Error> {
        atomic_replace(
            &file_clone,
            n as usize,
            &pgn_offsets,
            &pgn_meta,
            &pgn_locks,
            |parser, tmp| {
                // copy head up to insertion point
                let insert_pos = parser.position()?;
                let mut f = File::open(&file_clone)?;
                f.seek(SeekFrom::Start(0))?;
                let mut head = f.take(insert_pos);
                io::copy(&mut head, tmp.as_file_mut())?;

                // write new pgn
                tmp.as_file_mut().write_all(pgn_clone.as_bytes())?;

                // skip the game to be replaced in original and copy the remainder
                parser.skip_games(1)?;
                write_to_end(&mut parser.reader, tmp.as_file_mut())?;
                Ok(())
            },
        )
    })
    .await
    .map_err(|e| {
        Error::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("join error: {}", e),
        ))
    })??;

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
        let canon = std::fs::canonicalize(&file)
            .unwrap()
            .to_string_lossy()
            .to_string();
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
        use oauth2::basic::BasicClient;
        use oauth2::{
            AuthUrl, ClientId, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
            TokenUrl,
        };
        use std::net::SocketAddr;
        use std::sync::Arc;

        let connection_pool: DashMap<
            String,
            diesel::r2d2::Pool<diesel::r2d2::ConnectionManager<diesel::SqliteConnection>>,
        > = DashMap::new();
        let line_cache: DashMap<
            (crate::db::GameQueryJs, std::path::PathBuf),
            (
                Vec<crate::db::PositionStats>,
                Vec<crate::db::NormalizedGame>,
            ),
        > = DashMap::new();
        let db_cache = std::sync::Mutex::new(Vec::new());
        let new_request = Arc::new(tokio::sync::Semaphore::new(2));
        let pgn_offsets = DashMap::new();
        let pgn_index_meta = DashMap::new();
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
            pkce: Arc::new((
                pkce_challenge,
                PkceCodeVerifier::secret(&pkce_verifier).to_string(),
            )),
            client: Arc::new(client),
            socket_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        };

        let state = crate::AppState {
            connection_pool,
            line_cache,
            db_cache,
            new_request,
            pgn_offsets,
            pgn_index_meta,
            pgn_locks,
            fide_players,
            engine_processes,
            auth,
        };

        state.pgn_offsets.insert(key.clone(), vec![offset]);

        // test offset_by_index positions parser at the precomputed offset
        let mut parser = PgnParser::new(File::open(&file)?)?;
        parser.offset_by_index(100, &state.pgn_offsets, &state.pgn_index_meta, &key)?;
        let pos = parser.position()?;
        assert_eq!(pos, offset);

        // index 101 should be positioned after that offset
        parser.offset_by_index(101, &state.pgn_offsets, &state.pgn_index_meta, &key)?;
        let pos2 = parser.position()?;
        assert!(pos2 > offset);

        Ok(())
    }

    #[test]
    fn ignore_bom_and_read_game() -> std::io::Result<()> {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bom.pgn");
        let mut f = File::create(&file)?;

        // write BOM then a simple tagged game
        f.write_all(&[0xEF, 0xBB, 0xBF])?;
        writeln!(f, "[Event \"BOM Test\"]")?;
        writeln!(f, "\n1. e4 e5\n")?;
        f.flush()?;

        let mut parser = PgnParser::new(File::open(&file)?)?;
        let game = parser.read_game()?;

        assert!(game.contains("1. e4 e5"));
        Ok(())
    }

    #[test]
    fn leading_whitespace_tags_are_recognized() -> std::io::Result<()> {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lead.pgn");
        let mut f = File::create(&file)?;

        // two games with leading whitespace before tags
        for _ in 0..2 {
            writeln!(f, "   [Event \"Lead\"]")?;
            writeln!(f, "   \n1. e4 e5\n")?;
        }
        f.flush()?;

        let mut parser = PgnParser::new(File::open(&file)?)?;
        let first = parser.read_game()?;

        let second = parser.read_game()?;

        assert!(first.contains("1. e4 e5") && second.contains("1. e4 e5"));
        Ok(())
    }
}

#[test]
fn atomic_replace_op_failure_releases_lock() -> std::io::Result<()> {
    use dashmap::DashMap;
    use std::fs::OpenOptions;
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("atomic_fail.pgn");
    let mut f = File::create(&file)?;
    writeln!(f, "[Event \"X\"]")?;
    writeln!(f, "1. e4 e5")?;
    f.flush()?;

    let pgn_offsets: DashMap<String, Vec<u64>> = DashMap::new();
    let pgn_meta: DashMap<String, (u64, u64)> = DashMap::new();
    let pgn_locks: DashMap<String, Arc<Mutex<()>>> = DashMap::new();

    // Force the op closure to return an error.
    let res = atomic_replace(
        &file,
        0,
        &pgn_offsets,
        &pgn_meta,
        &pgn_locks,
        |_parser, _tmp| Err(std::io::Error::new(std::io::ErrorKind::Other, "boom")),
    );

    assert!(res.is_err());

    // Ensure the OS-level lock has been released by attempting a non-blocking
    // exclusive lock on the file.
    let mut f2 = OpenOptions::new().read(true).write(true).open(&file)?;
    f2.try_lock_exclusive()?;
    f2.unlock()?;

    Ok(())
}

#[test]
fn atomic_replace_concurrent_writers_atomic_replacement() -> std::io::Result<()> {
    use dashmap::DashMap;
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("atomic_concurrent.pgn");
    let mut f = File::create(&file)?;
    writeln!(f, "[Event \"Init\"]")?;
    writeln!(f, "1. e4 e5")?;
    f.flush()?;

    let pgn_offsets: DashMap<String, Vec<u64>> = DashMap::new();
    let pgn_meta: DashMap<String, (u64, u64)> = DashMap::new();
    let pgn_locks: DashMap<String, Arc<Mutex<()>>> = DashMap::new();

    let threads: Vec<_> = (0..8)
        .map(|i| {
            let file2 = file.clone();
            let offs = pgn_offsets.clone();
            let meta = pgn_meta.clone();
            let locks = pgn_locks.clone();
            std::thread::spawn(move || -> std::io::Result<()> {
                let content = format!("writer-{}", i);
                atomic_replace(&file2, 0, &offs, &meta, &locks, |_parser, tmp| {
                    tmp.as_file_mut().write_all(content.as_bytes())?;
                    Ok(())
                })
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            })
        })
        .collect();

    for t in threads {
        t.join().expect("thread panicked")?;
    }

    let final_content = std::fs::read_to_string(&file)?;
    // final content should match one of the writers exactly
    let ok = (0..8).any(|i| final_content == format!("writer-{}", i));
    assert!(ok, "final content not from any writer: {}", final_content);

    Ok(())
}

#[test]
fn skip_games_skips_correct_number_of_games() -> std::io::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("skip_games.pgn");
    let mut f = File::create(&file)?;

    // Write 5 games
    for i in 0..5 {
        writeln!(f, "[Event \"Game {}\"]", i)?;
        writeln!(f, "\n1. e4 e5\n")?;
    }
    f.flush()?;

    let mut parser = PgnParser::new(File::open(&file)?)?;
    let bytes_skipped = parser.skip_games(3)?;
    assert!(bytes_skipped > 0);

    // After skipping 3 games, the next game should be "Game 3"
    let game = parser.read_game()?;
    assert!(game.contains("[Event \"Game 3\"]"));

    Ok(())
}

#[test]
fn skip_games_zero_does_not_advance() -> std::io::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("skip_zero.pgn");
    let mut f = File::create(&file)?;
    writeln!(f, "[Event \"A\"]")?;
    writeln!(f, "1. e4 e5")?;
    f.flush()?;

    let mut parser = PgnParser::new(File::open(&file)?)?;
    let pos_before = parser.position()?;
    let skipped = parser.skip_games(0)?;
    let pos_after = parser.position()?;
    assert_eq!(skipped, 0);
    assert_eq!(pos_before, pos_after);

    Ok(())
}

#[test]
fn skip_games_handles_eof_gracefully() -> std::io::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("skip_eof.pgn");
    let mut f = File::create(&file)?;
    writeln!(f, "[Event \"A\"]")?;
    writeln!(f, "1. e4 e5")?;
    f.flush()?;

    let mut parser = PgnParser::new(File::open(&file)?)?;
    // Try to skip more games than exist
    let skipped = parser.skip_games(10)?;
    assert!(skipped > 0);

    // Should be at EOF now
    let game = parser.read_game()?;
    assert!(game.is_empty());

    Ok(())
}

#[test]
fn skip_games_with_leading_whitespace_tags() -> std::io::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("skip_leading_ws.pgn");
    let mut f = File::create(&file)?;
    for i in 0..3 {
        writeln!(f, "   [Event \"WS {}\"]", i)?;
        writeln!(f, "   \n1. d4 d5\n")?;
    }
    f.flush()?;

    let mut parser = PgnParser::new(File::open(&file)?)?;
    parser.skip_games(2)?;
    let game = parser.read_game()?;
    assert!(game.contains("[Event \"WS 2\"]"));

    Ok(())
}

#[test]
fn skip_games_returns_bytes_read() -> std::io::Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("skip_bytes.pgn");
    let mut f = File::create(&file)?;
    for i in 0..2 {
        writeln!(f, "[Event \"Bytes {}\"]", i)?;
        writeln!(f, "1. c4 c5")?;
    }
    f.flush()?;

    let mut parser = PgnParser::new(File::open(&file)?)?;
    let bytes = parser.skip_games(1)?;
    assert!(bytes > 0);

    Ok(())
}
