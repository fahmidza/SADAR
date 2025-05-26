# import pandas as pd
# import logging

# logger = logging.getLogger("DataProcessor")

# def load_and_sample_data(csv_path, n_samples_per_type=False, random_state=False, target_column='type'):
#     """
#     Memuat data dari file CSV dan mengambil sampel yang seimbang berdasarkan kolom target.
#     """
#     try:
#         df = pd.read_csv(csv_path)
#         logger.info(f"Dataset '{csv_path}' berhasil dimuat. Shape: {df.shape}")
#     except FileNotFoundError:
#         logger.error(f"Error: File dataset '{csv_path}' tidak ditemukan.")
#         return None
#     except Exception as e:
#         logger.error(f"Error saat memuat dataset '{csv_path}': {e}")
#         return None

#     if target_column not in df.columns:
#         logger.error(f"Error: Kolom target '{target_column}' tidak ditemukan dalam dataset.")
#         return df # Kembalikan df asli jika kolom target tidak ada untuk sampling

#     logger.info(f"Mengambil sampel {n_samples_per_type} data per '{target_column}'...")
#     try:
#         # Menggunakan group_keys=False untuk menghindari multi-index yang tidak perlu setelahnya
#         df_sample = df.groupby(target_column, group_keys=False).apply(
#             lambda x: x.sample(
#                 n=min(len(x), n_samples_per_type), # Ambil n_samples atau semua jika kurang
#                 random_state=random_state,
#                 replace=len(x) < n_samples_per_type # replace=True jika sampel lebih sedikit dari n
#             )
#         )
#         df_sample = df_sample.reset_index(drop=True)
#         logger.info(f"Berhasil mengambil sampel data. Jumlah sampel: {len(df_sample)}")
#         if len(df_sample) == 0:
#              logger.warning("DataFrame sampel kosong. Periksa data input dan parameter sampling.")
#              return df # Kembalikan df asli jika sampel kosong
#         return df_sample
#     except Exception as e:
#         logger.error(f"Error saat mengambil sampel data: {e}")
#         logger.info("Mengembalikan DataFrame asli karena sampling gagal.")
#         return df

import pandas as pd
import logging

logger = logging.getLogger("DataProcessor")

import pandas as pd
import numpy as np

def stratified_sample(df, stratify_col, n_samples, random_state=None):
    # Hitung proporsi tiap kelas
    prop = df[stratify_col].value_counts(normalize=True)
    
    # Hitung jumlah sampel tiap kelas (round supaya total mendekati n_samples)
    samples_per_class = (prop * n_samples).round().astype(int)
    
    # Karena pembulatan bisa bikin total berbeda, sesuaikan
    diff = n_samples - samples_per_class.sum()
    if diff > 0:
        # Tambahkan 1 ke kelas dengan frekuensi terbanyak sampai total genap
        for cls in samples_per_class.index:
            if diff == 0:
                break
            samples_per_class[cls] += 1
            diff -= 1
    elif diff < 0:
        # Kurangi 1 dari kelas dengan frekuensi terbanyak sampai total genap
        for cls in samples_per_class.index:
            if diff == 0:
                break
            if samples_per_class[cls] > 1:
                samples_per_class[cls] -= 1
                diff += 1

    # Sampling tiap kelas
    sampled_dfs = []
    for cls, n in samples_per_class.items():
        cls_subset = df[df[stratify_col] == cls]
        # Jika data kelas kurang dari n, pakai replace=True
        replace_flag = len(cls_subset) < n
        sampled = cls_subset.sample(n=n, random_state=random_state, replace=replace_flag)
        sampled_dfs.append(sampled)

    # Gabung semua sampel
    stratified_sample_df = pd.concat(sampled_dfs).reset_index(drop=True)
    return stratified_sample_df


def load_and_sample_data(csv_path, n_samples_per_type=False, random_state=False, target_column='type'):
    """
    Memuat data dari file CSV dan mengembalikan seluruh data tanpa sampling.
    """
    try:
        df = pd.read_csv(csv_path)
        # Simpan indeks asli ke kolom 'original_index'
        df['original_index'] = df.index
        
        # Stratified sampling df berdasarkan kolom target, total 5000 data
        df = stratified_sample(df, target_column, 50000, random_state)
        logger.info(f"Dataset '{csv_path}' berhasil dimuat. Shape: {df.shape}")
    except FileNotFoundError:
        logger.error(f"Error: File dataset '{csv_path}' tidak ditemukan.")
        return None
    except Exception as e:
        logger.error(f"Error saat memuat dataset '{csv_path}': {e}")
        return None

    if target_column not in df.columns:
        logger.warning(f"Kolom target '{target_column}' tidak ditemukan dalam dataset. Mengembalikan data lengkap.")
        return df

    # Langsung kembalikan semua data tanpa sampling
    logger.info(f"Mengembalikan seluruh data tanpa sampling.")
    return df
