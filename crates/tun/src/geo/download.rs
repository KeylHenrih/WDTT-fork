//! Downloading and caching of the v2ray geo data files.
//!
//! The files are fetched from the `Loyalsoldier/v2ray-rules-dat` release
//! assets and cached on disk. A cached copy is reused until it is older than
//! the configured maximum age, so a client start does not depend on the
//! network being reachable.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::GeoData;

/// Default release URL for `geoip.dat`.
pub const DEFAULT_GEOIP_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat";

/// Default release URL for `geosite.dat`.
pub const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat";

/// Default maximum age of a cached file before a refresh is attempted.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Errors raised while fetching or loading geo data.
#[derive(Debug, thiserror::Error)]
pub enum GeoError {
    /// A network request failed.
    #[error("geo download failed: {0}")]
    Network(String),
    /// A file could not be read or written.
    #[error("geo file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A downloaded or cached file could not be decoded.
    #[error("geo parse error: {0}")]
    Parse(#[from] super::GeoParseError),
    /// The HTTP response carried a non-success status.
    #[error("geo download returned HTTP {0}")]
    HttpStatus(u16),
}

/// Paths of the two cached geo files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoFiles {
    /// Path of the cached `geoip.dat`.
    pub geoip: PathBuf,
    /// Path of the cached `geosite.dat`.
    pub geosite: PathBuf,
}

impl GeoFiles {
    /// Returns the conventional cache paths under `dir`.
    #[must_use]
    pub fn under(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            geoip: dir.join("geoip.dat"),
            geosite: dir.join("geosite.dat"),
        }
    }
}

/// Downloads geo data and keeps it in an on-disk cache.
#[derive(Debug, Clone)]
pub struct GeoDownloader {
    files: GeoFiles,
    geoip_url: String,
    geosite_url: String,
    max_age: Duration,
}

impl GeoDownloader {
    /// Creates a downloader writing into `files`.
    #[must_use]
    pub fn new(files: GeoFiles) -> Self {
        Self {
            files,
            geoip_url: DEFAULT_GEOIP_URL.to_owned(),
            geosite_url: DEFAULT_GEOSITE_URL.to_owned(),
            max_age: DEFAULT_MAX_AGE,
        }
    }

    /// Overrides the download URLs, for mirrors or tests.
    #[must_use]
    pub fn with_urls(mut self, geoip: impl Into<String>, geosite: impl Into<String>) -> Self {
        self.geoip_url = geoip.into();
        self.geosite_url = geosite.into();
        self
    }

    /// Overrides the maximum age of a cached file.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Returns the cache paths in use.
    #[must_use]
    pub fn files(&self) -> &GeoFiles {
        &self.files
    }

    /// Loads geo data, downloading only what is missing or stale.
    ///
    /// A stale cache is still used when the download fails, so a client can
    /// start offline with the last known data.
    ///
    /// # Errors
    ///
    /// Returns [`GeoError`] when no usable data can be produced at all.
    pub async fn load(&self) -> Result<GeoData, GeoError> {
        let geoip = self.ensure(&self.files.geoip, &self.geoip_url).await?;
        let geosite = self.ensure(&self.files.geosite, &self.geosite_url).await?;

        let mut data = GeoData::default();
        data.load_geoip(&geoip)?;
        data.load_geosite(&geosite)?;
        Ok(data)
    }

    /// Loads geo data from the cache only, never touching the network.
    ///
    /// # Errors
    ///
    /// Returns [`GeoError::Io`] when a cache file is missing or unreadable.
    pub fn load_cached(&self) -> Result<GeoData, GeoError> {
        let geoip = std::fs::read(&self.files.geoip)?;
        let geosite = std::fs::read(&self.files.geosite)?;
        let mut data = GeoData::default();
        data.load_geoip(&geoip)?;
        data.load_geosite(&geosite)?;
        Ok(data)
    }

    /// Returns the cached bytes for `path`, refreshing them when stale.
    async fn ensure(&self, path: &Path, url: &str) -> Result<Vec<u8>, GeoError> {
        let cached = std::fs::read(path).ok();
        let fresh = cached.is_some() && !self.is_stale(path);

        if fresh {
            return Ok(cached.expect("checked above"));
        }

        match self.download(url).await {
            Ok(bytes) => {
                self.store(path, &bytes)?;
                Ok(bytes)
            }
            Err(err) => match cached {
                Some(bytes) => {
                    tracing::warn!(
                        "geo refresh failed for {} ({err}); using cached copy",
                        path.display()
                    );
                    Ok(bytes)
                }
                None => Err(err),
            },
        }
    }

    /// Returns true when `path` is older than the configured maximum age.
    fn is_stale(&self, path: &Path) -> bool {
        let Ok(meta) = std::fs::metadata(path) else {
            return true;
        };
        let Ok(modified) = meta.modified() else {
            return true;
        };
        match SystemTime::now().duration_since(modified) {
            Ok(age) => age > self.max_age,
            // A modification time in the future is treated as stale.
            Err(_) => true,
        }
    }

    /// Writes `bytes` to `path`, creating the parent directory as needed.
    fn store(&self, path: &Path, bytes: &[u8]) -> Result<(), GeoError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write to a temporary file first so a crash cannot leave a truncated
        // cache behind.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Fetches `url` and returns the response body.
    async fn download(&self, url: &str) -> Result<Vec<u8>, GeoError> {
        let response = reqwest::get(url)
            .await
            .map_err(|e| GeoError::Network(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(GeoError::HttpStatus(status.as_u16()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| GeoError::Network(e.to_string()))?;
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_paths_are_derived_from_directory() {
        let files = GeoFiles::under("/tmp/geo");
        assert_eq!(files.geoip, PathBuf::from("/tmp/geo/geoip.dat"));
        assert_eq!(files.geosite, PathBuf::from("/tmp/geo/geosite.dat"));
    }

    #[test]
    fn missing_file_is_stale() {
        let dir = std::env::temp_dir().join("wdtt-geo-test-missing");
        let downloader = GeoDownloader::new(GeoFiles::under(&dir));
        assert!(downloader.is_stale(&dir.join("nope.dat")));
    }

    #[test]
    fn fresh_file_is_not_stale() {
        let dir = std::env::temp_dir().join("wdtt-geo-test-fresh");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fresh.dat");
        std::fs::write(&path, b"x").unwrap();

        let downloader = GeoDownloader::new(GeoFiles::under(&dir));
        assert!(!downloader.is_stale(&path));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn zero_max_age_makes_everything_stale() {
        let dir = std::env::temp_dir().join("wdtt-geo-test-zero");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("any.dat");
        std::fs::write(&path, b"x").unwrap();

        let downloader = GeoDownloader::new(GeoFiles::under(&dir)).with_max_age(Duration::ZERO);
        assert!(downloader.is_stale(&path));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn store_writes_atomically_and_creates_parents() {
        let dir = std::env::temp_dir().join("wdtt-geo-test-store/nested");
        let downloader = GeoDownloader::new(GeoFiles::under(&dir));
        let path = dir.join("out.dat");
        downloader.store(&path, b"payload").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"payload");
        assert!(!path.with_extension("tmp").exists());

        std::fs::remove_dir_all(std::env::temp_dir().join("wdtt-geo-test-store")).ok();
    }

    #[test]
    fn load_cached_reads_both_files() {
        let dir = std::env::temp_dir().join("wdtt-geo-test-cached");
        std::fs::create_dir_all(&dir).unwrap();
        let files = GeoFiles::under(&dir);
        std::fs::write(&files.geoip, []).unwrap();
        std::fs::write(&files.geosite, []).unwrap();

        let downloader = GeoDownloader::new(files);
        let data = downloader.load_cached().unwrap();
        assert!(data.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_cached_reports_missing_files() {
        let dir = std::env::temp_dir().join("wdtt-geo-test-absent");
        let downloader = GeoDownloader::new(GeoFiles::under(&dir));
        assert!(matches!(downloader.load_cached(), Err(GeoError::Io(_))));
    }
}
