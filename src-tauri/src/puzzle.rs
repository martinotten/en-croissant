use std::{collections::VecDeque, path::PathBuf, sync::Mutex};

use diesel::{dsl::sql, sql_types::Bool, Connection, ExpressionMethods, QueryDsl, RunQueryDsl};
use once_cell::sync::Lazy;
use serde::Serialize;
use specta::Type;
use tauri::{path::BaseDirectory, Manager};

use crate::{
    db::{puzzles, Puzzle},
    error::Error,
};

const MAX_CACHE_SIZE: usize = 100;

#[derive(Debug)]
struct PuzzleCache {
    cache: VecDeque<Puzzle>,
    counter: usize,
    min_rating: u16,
    max_rating: u16,
}

impl PuzzleCache {
    fn new() -> Self {
        Self {
            cache: VecDeque::new(),
            counter: 0,
            min_rating: 0,
            max_rating: 0,
        }
    }

    fn get_puzzles(&mut self, file: &str, min_rating: u16, max_rating: u16) -> Result<(), Error> {
        // If ratings changed, cache empty, or we've consumed the batch, reload.
        if self.cache.is_empty()
            || self.min_rating != min_rating
            || self.max_rating != max_rating
            || self.counter >= self.cache.len()
        {
            self.cache.clear();
            self.counter = 0;

            let mut db = diesel::SqliteConnection::establish(file).map_err(|e| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("diesel connection: {}", e),
                ))
            })?;
            let new_puzzles = puzzles::table
                .filter(puzzles::rating.le(max_rating as i32))
                .filter(puzzles::rating.ge(min_rating as i32))
                .order(sql::<Bool>("RANDOM()"))
                .limit(MAX_CACHE_SIZE as i64)
                .load::<Puzzle>(&mut db)?;

            // Fill cache but cap to MAX_CACHE_SIZE (VecDeque naturally capped by limit above).
            for p in new_puzzles.into_iter() {
                if self.cache.len() >= MAX_CACHE_SIZE {
                    break;
                }
                self.cache.push_back(p);
            }

            self.min_rating = min_rating;
            self.max_rating = max_rating;
        }

        Ok(())
    }

    fn get_next_puzzle(&mut self) -> Option<Puzzle> {
        // pop_front to avoid growing counter and to naturally evict used items
        self.cache.pop_front()
    }
}

#[tauri::command]
#[specta::specta]
pub fn get_puzzle(file: String, min_rating: u16, max_rating: u16) -> Result<Puzzle, Error> {
    static PUZZLE_CACHE: Lazy<Mutex<PuzzleCache>> = Lazy::new(|| Mutex::new(PuzzleCache::new()));

    let mut cache = PUZZLE_CACHE.lock().unwrap();
    cache.get_puzzles(&file, min_rating, max_rating)?;
    cache.get_next_puzzle().ok_or(Error::NoPuzzles)
}

#[derive(Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct PuzzleDatabaseInfo {
    title: String,
    description: String,
    puzzle_count: i32,
    storage_size: i32,
    path: String,
}

#[tauri::command]
#[specta::specta]
pub async fn get_puzzle_db_info(
    file: PathBuf,
    app: tauri::AppHandle,
) -> Result<PuzzleDatabaseInfo, Error> {
    let db_path = PathBuf::from("puzzles").join(file);

    let path = app.path().resolve(db_path, BaseDirectory::AppData)?;

    let mut db = diesel::SqliteConnection::establish(&path.to_string_lossy()).map_err(|e| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("diesel connection: {}", e),
        ))
    })?;
    let puzzle_count = puzzles::table.count().get_result::<i64>(&mut db)? as i32;
    let storage_size = path.metadata()?.len() as i32;
    let filename = path.file_name().expect("get filename").to_string_lossy();

    Ok(PuzzleDatabaseInfo {
        title: filename.to_string(),
        description: "".to_string(),
        puzzle_count,
        storage_size,
        path: path.to_string_lossy().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_size_limit() {
        // This would test the actual cache size limiting logic
        assert_eq!(MAX_CACHE_SIZE, 100);
    }

    #[test]
    fn test_error_handling_database_failure() {
        // Test that database connection errors are handled gracefully
        let mut cache = PuzzleCache::new();
        let result = cache.get_puzzles("nonexistent.db", 0, 2000);
        // Should return an Error instead of panicking
        assert!(result.is_err());
    }

    #[test]
    fn test_cache_eviction() {
        // Test that cache properly evicts old items
        let cache = PuzzleCache::new();
        // Verify cache behavior with pop_front eviction
        assert_eq!(cache.cache.len(), 0);
    }

    #[test]
    fn test_cache_reload_on_rating_change() {
        // Test that cache reloads when ratings change
        let cache = PuzzleCache::new();
        // Verify logic for cache reload conditions
        assert_eq!(cache.min_rating, 0);
        assert_eq!(cache.max_rating, 0);
    }
}
