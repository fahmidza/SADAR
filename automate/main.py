import pandas as pd
import logging
from tqdm import tqdm # Untuk progress bar

# Impor fungsi dari file lain
from feature_extractor import extract_features
from data_processor import load_and_sample_data
import config # Impor konfigurasi

# Mengatur logging utama
logging.basicConfig(
    level=logging.INFO, # Bisa diubah ke DEBUG untuk detail lebih
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
main_logger = logging.getLogger("MainScript")

def main():
    main_logger.info("Memulai skrip utama ekstraksi fitur URL.")

    # 1. Memuat dan mengambil sampel data
    main_logger.info(f"Memuat data dari: {config.DATASET_PATH}")
    df_sampled = load_and_sample_data(
        config.DATASET_PATH,
        n_samples_per_type=config.N_SAMPLES_PER_TYPE,
        random_state=config.RANDOM_STATE,
        target_column=config.TARGET_COLUMN
    )

    if df_sampled is None or df_sampled.empty:
        main_logger.error("Tidak ada data untuk diproses setelah sampling. Skrip dihentikan.")
        return

    if config.URL_COLUMN not in df_sampled.columns:
        main_logger.error(f"Kolom URL '{config.URL_COLUMN}' tidak ditemukan dalam data sampel. Skrip dihentikan.")
        return

    # 2. Ekstraksi fitur
    main_logger.info(f"Memulai ekstraksi fitur untuk {len(df_sampled)} URL...")
    features_list = []
    
    # Menggunakan tqdm untuk progress bar
    for url in tqdm(df_sampled[config.URL_COLUMN], desc="Mengekstrak Fitur"):
        try:
            features = extract_features(url)
            features_list.append(features)
        except Exception as e:
            main_logger.error(f"Gagal total mengekstrak fitur untuk URL: {url}. Error: {e}")
            # Mengisi dengan None sebanyak jumlah fitur yang diharapkan
            features_list.append([None] * len(config.FEATURE_COLUMNS)) 

    main_logger.info("Selesai ekstraksi semua fitur.")

    # 3. Membuat DataFrame dari fitur
    features_df = pd.DataFrame(features_list)

    # 4. Menetapkan nama kolom
    if features_df.shape[1] == len(config.FEATURE_COLUMNS):
        features_df.columns = config.FEATURE_COLUMNS
        main_logger.info("Nama kolom berhasil ditetapkan untuk DataFrame fitur.")
    else:
        main_logger.warning(
            f"Jumlah fitur yang diekstrak ({features_df.shape[1]}) "
            f"tidak sesuai dengan jumlah nama kolom yang diharapkan ({len(config.FEATURE_COLUMNS)}). "
            "Nama kolom akan menjadi generik."
        )
        # Opsional: buat nama kolom generik jika terjadi ketidaksesuaian
        features_df.columns = [f'feature_{i+1}' for i in range(features_df.shape[1])]

    # 5. Menambahkan kolom target kembali (jika ada dan valid)
    if config.TARGET_COLUMN in df_sampled.columns:
        features_df[config.TARGET_COLUMN] = df_sampled[config.TARGET_COLUMN].values
        main_logger.info(f"Kolom target '{config.TARGET_COLUMN}' berhasil ditambahkan ke DataFrame fitur.")
    else:
        main_logger.warning(f"Kolom target '{config.TARGET_COLUMN}' tidak ditemukan di data sampel, tidak ditambahkan.")

    # 5.a. Menambahkan kolom url_original ke DataFrame fitur
    if config.URL_COLUMN in df_sampled.columns:
        features_df['url_original'] = df_sampled[config.URL_COLUMN].values
        main_logger.info(f"Kolom URL asli '{config.URL_COLUMN}' berhasil ditambahkan sebagai 'url_original'.")
    else:
        main_logger.warning(f"Kolom URL '{config.URL_COLUMN}' tidak ditemukan di data sampel, kolom 'url_original' tidak ditambahkan.")

    # 5.b. Menambahkan kolom indeks asli (original_index)
    # Tambahkan kolom indeks asli ke DataFrame fitur
    if 'original_index' in df_sampled.columns:
        features_df['original_index'] = df_sampled['original_index'].values
        main_logger.info("Kolom 'original_index' berhasil ditambahkan ke DataFrame fitur.")
    else:
        main_logger.warning("Kolom 'original_index' tidak ditemukan di data sampel, tidak ditambahkan.")




    # 6. Menampilkan hasil dan menyimpan (opsional)
    main_logger.info("DataFrame fitur hasil ekstraksi (5 baris pertama):")
    print(features_df.head())
    main_logger.info(f"Shape dari DataFrame fitur: {features_df.shape}")

    try:
        features_df.to_csv(config.OUTPUT_CSV_PATH, index=False)
        main_logger.info(f"DataFrame fitur berhasil disimpan ke: {config.OUTPUT_CSV_PATH}")
    except Exception as e:
        main_logger.error(f"Gagal menyimpan DataFrame fitur ke CSV: {e}")

    main_logger.info("Skrip utama ekstraksi fitur selesai.")

if __name__ == "__main__":
    main()