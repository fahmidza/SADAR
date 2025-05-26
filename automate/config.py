# Konfigurasi untuk skrip ekstraksi fitur

DATASET_PATH = 'automate/df_remaining_Chandra.csv' # Path ke file dataset Anda
N_SAMPLES_PER_TYPE = 50 # Jumlah sampel yang diambil per 'type'
RANDOM_STATE = 42
TARGET_COLUMN = 'type' # Nama kolom yang berisi label/tipe URL
URL_COLUMN = 'url'     # Nama kolom yang berisi URL

# Daftar nama kolom fitur sesuai urutan di feature_extractor.py
FEATURE_COLUMNS = [
    'IP_Address_Feature',             # 1. Hasilnya -1 atau 1
    'URL_Length_Val',                 # 2. Nilai asli panjang URL
    'URL_Shortening_Service',         # 3. Hasilnya -1 atau 1
    'Double_Slash_Redirect',          # 4. Hasilnya -1 atau 1
    'Hyphen_In_Domain',               # 5. Hasilnya -1 atau 1
    'Subdomain_Dot_Count_Val',        # 6. Nilai asli jumlah titik
    'Uses_HTTPS_Protocol',            # 7. Hasilnya -1 atau 1
    # 'Domain_Expiration_Days_Val',     # 8. Nilai asli sisa hari (bisa negatif)
    'Favicon_From_Same_Domain',       # 9. Hasilnya -1 atau 1
    'Uses_Custom_Port',               # 10. Hasilnya -1 atau 1
    'Ext_Resource_Ratio_Pct_Val',     # 11. Nilai asli persentase (0-100), -1.0 jika error
    'Ext_Links_Ratio_Pct_Val',        # 12. Nilai asli persentase "unsafe" (0-100), -1.0 jika error
    'Ext_CSS_JS_Ratio_Pct_Val',       # 13. Nilai asli persentase "same domain" (0-100), -1.0 jika error
    'External_Form_Action',           # 14. Hasilnya -1, atau 1
    'Form_Submits_To_Email',          # 15. Hasilnya -1 atau 1
    'Page_Has_Content',               # 16. Hasilnya -1, atau 1
    'Num_Redirects_Val',              # 17. Nilai asli jumlah redirect, -1 jika error
    'Mouseover_Link_Manipulation',    # 18. Hasilnya -1 atau 1
    'Right_Click_Disabled',           # 19. Hasilnya -1 atau 1
    'Popup_Window_Usage',             # 20. Hasilnya -1 atau 1
    'Iframe_Usage',                   # 21. Hasilnya -1 atau 1
    # 'Domain_Age_Months_Val',          # 22. Nilai asli usia domain dalam bulan, -1 jika error/tidak ada
    'Whois_Data_And_Valid_Expiry',    # 23. Hasilnya -1 atau 1 (berdasarkan domain_reg_len_feature)
    'URL_In_Static_Blacklist',        # 24. Hasilnya -1 atau 1
    # 'Domain_Registrant_Is_Company'    # 25. Hasilnya -1 atau 1
]

OUTPUT_CSV_PATH = 'extracted_features_dataset.csv' # Path untuk menyimpan hasil