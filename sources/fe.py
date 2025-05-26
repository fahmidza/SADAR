import re
import requests
from bs4 import BeautifulSoup
import ipaddress
import whois # Pastikan library 'whois' atau 'python-whois' terinstal
from datetime import datetime
from urllib.parse import urlparse
import socket
from googlesearch import search # Pastikan library 'google' atau 'googlesearch-python' terinstal
import logging # Import modul logging
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO, # Atur level logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("FeatureExtractor")

# Extract Feature
def diff_month(d1, d2):
    # Quick fix: handle list case
    if isinstance(d2, list):
        valid_dates = [d for d in d2 if hasattr(d, 'year')]
        if valid_dates:
            d2 = min(valid_dates)
        else:
            return -1
    
    if d2 is None or not hasattr(d2, 'year'):
        return -1
        
    return (d1.year - d2.year) * 12 + d1.month - d2.month

def extract_features(url_input):
    start_all = time.time() # Mulai timer untuk pengukuran waktu total
    logger.info(f"Memulai ekstraksi fitur untuk URL: {url_input}")
    data_set = []
    current_url = url_input # Gunakan variabel lokal
    
    # Converts the given URL into standard format
    if not re.match(r"^https?", current_url): # mencari url jika tidak ada https
        current_url = "http://" + current_url 
        logger.debug(f"URL dinormalisasi menjadi: {current_url}") 

    # Stores the response of the given URL
    response = ""
    soup = -999
    try:
        logger.debug(f"Mencoba mengambil konten dari URL: {current_url}")
        response = requests.get(current_url, timeout=10)
        response.raise_for_status() # Akan raise HTTPError untuk status kode 4xx/5xx
        soup = BeautifulSoup(response.text, 'html.parser')
        logger.debug(f"Berhasil mengambil konten dari URL: {current_url}")
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error saat mengambil URL '{current_url}': {http_err}")
        # response tetap "" dan soup tetap -999
    except requests.exceptions.ConnectionError as conn_err:
        logger.error(f"Connection error saat mengambil URL '{current_url}': {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        logger.error(f"Timeout saat mengambil URL '{current_url}': {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        logger.error(f"Error lain (requests) saat mengambil URL '{current_url}': {req_err}")
    except Exception as e: # Tangkap error parsing BeautifulSoup juga
        logger.error(f"Error umum saat memproses respons atau parsing HTML untuk URL '{current_url}': {e}")


    # Extracts domain from the given URL
    domain = ""
    try:
        domain_match = re.findall(r"://([^/]+)/?", current_url)
        if domain_match:
            domain = domain_match[0]
            if re.match(r"^www.",domain):
                domain = domain.replace("www.","")
            logger.debug(f"Domain diekstrak: '{domain}' dari URL: '{current_url}'")
        else:
            logger.warning(f"Tidak dapat mengekstrak domain dari URL: '{current_url}'")
    except Exception as e:
        logger.error(f"Error saat mengekstrak domain dari URL '{current_url}': {e}")


    # Requests all the information about the domain
    whois_response = None
    if domain:
        logger.info(f"Mencoba query WHOIS untuk domain: '{domain}' (dari URL: '{current_url}')")
        try:
            whois_response = whois.whois(domain)
            if whois_response and not whois_response.get('domain_name'): # Cek jika respons kosong atau tidak valid
                 if whois_response.text and "Connection timed out" in whois_response.text: # Cek output mentah jika ada
                      logger.error(f"WHOIS query untuk domain '{domain}' (dari URL '{current_url}') timeout (terdeteksi dari teks).")
                      whois_response = None # Set ke None jika timeout
                 elif whois_response.text: # Jika ada teks lain, itu mungkin hasil parsial atau error
                      logger.warning(f"WHOIS query untuk domain '{domain}' (dari URL '{current_url}') mengembalikan data yang tidak lengkap atau error parsing: {str(whois_response)[:200]}") # Log sebagian kecil dari respons
                      # Biarkan whois_response apa adanya jika ada data parsial, atau set ke None jika dianggap gagal total
                 else: # whois_response ada tapi tidak ada domain_name dan tidak ada text error
                      logger.warning(f"WHOIS query untuk domain '{domain}' (dari URL '{current_url}') berhasil tapi data domain_name tidak ditemukan.")
            elif whois_response:
                 logger.info(f"WHOIS query untuk domain '{domain}' (dari URL '{current_url}') berhasil.")

        except whois.parser.WhoisCommandFailed as wcf:
            logger.error(f"WHOIS command failed untuk domain '{domain}' (dari URL '{current_url}'): {wcf}")
            whois_response = None
        except Exception as e: # Menangkap semua error lain dari whois, termasuk timeout dari socket
            logger.error(f"WHOIS query untuk domain '{domain}' (dari URL '{current_url}') gagal: {type(e)._name_} - {e}")
            whois_response = None # Pastikan None jika gagal
    else:
        logger.warning(f"Query WHOIS dilewati karena domain tidak berhasil diekstrak dari URL: '{current_url}'")

    # 1.IP_Address
    # Fitur ini memeriksa apakah URL itu sendiri adalah alamat IP.
    # Jika URL adalah alamat IP, itu dianggap mencurigakan (-1). Jika tidak (artinya berbasis domain), dianggap aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    try:
        # Coba parse netloc dari URL sebagai IP. Jika domain adalah IP, itu mencurigakan.
        # Perlu diingat bahwa url di sini adalah URL lengkap, bukan hanya domain.
        # Misalnya, "http://192.168.1.1/path"
        # Kita harus mengekstrak bagian hostname dari URL untuk pemeriksaan IP yang akurat.
        parsed_url_for_ip_check = urlparse(current_url)
        # Cek apakah netloc adalah alamat IP
        ipaddress.ip_address(parsed_url_for_ip_check.netloc)
        data_set.append(-1)
    except ValueError: # ValueError jika netloc bukan alamat IP yang valid
        data_set.append(1)
    except Exception: # Tangkap error lain yang mungkin terjadi
        data_set.append(-1) # Jika ada error parsing, anggap mencurigakan
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur IP_Address: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi


    # 2.URL_Length
    # Fitur ini menilai keamanan URL berdasarkan panjangnya.
    # URL pendek (<54 char) dianggap aman (1).
    # URL sedang (54-75 char) dianggap normal (0).
    # URL panjang (>75 char) dianggap berbahaya/phishing (-1).
    
    # Masukkan panjang URL ke dalam data_set
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    data_set.append(len(current_url)) # Tambahkan panjang URL sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur URL_Length: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # if len(current_url) < 65:
    #     data_set.append(1)  # Dianggap aman
    # else:
    #     data_set.append(-1)  # Dianggap normal
    
    # 3. URL_Shortening
    # Fitur ini memeriksa apakah URL menggunakan layanan pemendek URL yang diketahui.
    # Jika menggunakan layanan pemendek, dianggap mencurigakan (-1). Jika tidak, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    match = re.search(
        r'1url\.com|adf\.ly|bc\.vc|bit\.do|bit\.ly|bitly\.com|bkite\.com|bl\.ink|BudURL\.com|buzurl\.com|'
        r'cli\.gs|cur\.lv|cutt\.ly|cutt\.us|db\.tt|doiop\.com|ff\.im|fic\.kr|filoops\.info|go2l\.ink|'
        r'goo\.gl|is\.gd|ity\.im|j\.mp|Just\.as|kl\.am|link\.zip\.net|lnkd\.in|loopt\.us|migre\.me|'
        r'om\.ly|ow\.ly|ping\.fm|po\.st|post\.ly|prettylinkpro\.com|q\.gs|qr\.ae|qr\.net|rebrand\.ly|'
        r'rubyurl\.com|short\.ie|short\.io|short\.to|shorte\.st|snip\.ly|snipr\.com|snipurl\.com|'
        r'scrnch\.me|su\.pr|t\.co|t2m\.io|tiny\.cc|tinyurl\.com|to\.ly|tr\.im|tweez\.me|twit\.ac|'
        r'twitthis\.com|twurl\.nl|u\.bb|u\.to|url4\.eu|v\.gd|vzturl\.com|wp\.me|x\.co|yfrog\.com|yourls\.org',
        current_url
    ) # Tambahkan domain shortener lain jika ada yang terbaru
    if match:
        data_set.append(-1)
    else:
        data_set.append(1)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur URL_Shortening: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 4.Double_Slash_Redirect_After_HTTPS
    # Fitur ini memeriksa keberadaan "//" di luar bagian protokol (misalnya, "http://").
    # Jika "//" ditemukan setelah posisi ke-6, dianggap mencurigakan (-1). Jika tidak, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    slash_indices = [match.start() for match in re.finditer('//', current_url)]
    if not slash_indices: # Tidak ada "//" sama sekali (seharusnya tidak mungkin untuk URL yang valid)
        data_set.append(1) # Atau -1 jika ini dianggap sebagai format URL yang salah
    # Jika posisi '//' terakhir lebih besar dari indeks 6 (artinya muncul setelah "http://" atau "https://")
    elif slash_indices[-1] > 6:
        data_set.append(-1)
    else:
        data_set.append(1)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Double_Slash_Redirect_After_HTTPS: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 5.Hyphen_in_Domain_Name
    # Fitur ini memeriksa apakah ada tanda hubung "-" di dalam nama domain.
    # Keberadaan tanda hubung di domain (misal, 'contoh-domain.com') dianggap mencurigakan (-1).
    # Jika tidak ada, dianggap normal/aman (1).
    # Variabel 'domain' sudah berisi hostname seperti 'contoh-domain.com'.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    if domain and "-" in domain: # Pastikan domain tidak kosong sebelum dicek
        data_set.append(-1) # Mencurigakan jika ada tanda hubung di domain
    else:
        data_set.append(1)  # Normal jika tidak ada, atau jika domain kosong (dianggap aman default)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Hyphen_in_Domain_Name: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 6. Presence_of_Subdomain
    # Fitur ini menilai keamanan berdasarkan jumlah tingkat subdomain.
    # Satu titik (misal, 'example.com') dianggap aman (1).
    # Dua titik (misal, 'shop.example.com') dianggap normal (0).
    # Lebih dari dua titik (misal, 'secure.shop.example.com') dianggap mencurigakan (-1).
    # if domain: # Hanya proses jika domain ada
    #     domain_dot_count = domain.count('.')
    #     if domain_dot_count < 3:
    #         data_set.append(1)
    #     else: # Termasuk 0 titik (misal, 'localhost') atau >2 titik
    #         data_set.append(-1)
    # else:
    #     data_set.append(-1) # Jika domain tidak bisa diekstrak, anggap mencurigakan
    # Masukkan jumlah titik sebagai fitur
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    data_set.append(current_url.count('.')) # Tambahkan jumlah titik sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Presence_of_Subdomain: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi


    # 7.Uses_HTTPS_Protocol
    # Fitur ini mengevaluasi penggunaan HTTPS dan keberhasilan koneksi.
    # Tidak HTTPS: -1 (berbahaya).
    # HTTPS tapi koneksi gagal (masalah SSL/sertifikat): 0 (normal/mencurigakan).
    # HTTPS dan koneksi berhasil: 1 (aman).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    if not current_url.startswith('https://'):
        data_set.append(-1)
    else:
        if response == "": # response adalah string kosong jika requests.get() gagal di awal
            data_set.append(1)
        else:
            data_set.append(-1)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Uses_HTTPS_Protocol: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi


    # 8.Domain_Expiration_Remaining
    # Fitur ini memeriksa sisa masa aktif domain dari data WHOIS.
    # Jika tidak ada tanggal kedaluwarsa atau sisa masa aktif <= 1 tahun, dianggap mencurigakan (-1).
    # Jika sisa masa aktif > 1 tahun, dianggap aman (1).
    # Variabel 'whois_response' sudah berisi hasil query WHOIS.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    registration_length_days = 0 # Inisialisasi
    domain_reg_len_feature = -1 # Default mencurigakan

    if whois_response and hasattr(whois_response, 'expiration_date'):
        whois_expiration_date_val = whois_response.expiration_date
        try:
            processed_expiration_date = None
            if whois_expiration_date_val is None:
                domain_reg_len_feature = -1
            else:
                if isinstance(whois_expiration_date_val, list):
                    valid_dates = [d for d in whois_expiration_date_val if isinstance(d, datetime)]
                    if valid_dates:
                        processed_expiration_date = min(valid_dates)
                elif isinstance(whois_expiration_date_val, datetime):
                    processed_expiration_date = whois_expiration_date_val

                if processed_expiration_date is None:
                    domain_reg_len_feature = -1
                else:
                    today = datetime.now()
                    time_difference = processed_expiration_date - today
                    registration_length_days = time_difference.days # Bisa negatif jika sudah kedaluwarsa

                    if registration_length_days <= 365: # Termasuk yang sudah kedaluwarsa
                        domain_reg_len_feature = -1
                    else:
                        domain_reg_len_feature = 1
        except (TypeError, ValueError) as e:
            # print(f"Error processing domain registration length for {domain}: {e}")
            domain_reg_len_feature = -1
        except Exception as e:
            # print(f"Unexpected error for domain registration length {domain}: {e}")
            domain_reg_len_feature = -1
    else: # whois_response None atau tidak ada expiration_date
        domain_reg_len_feature = -1
    # data_set.append(domain_reg_len_feature)
    # Masukkan sisa masa aktif domain sebagai fitur
    data_set.append(registration_length_days) # Tambahkan sisa masa aktif domain dalam hari sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Domain_Expiration_Remaining: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 9.Favicon_Source_Consistency
    # Fitur ini memeriksa apakah favicon halaman berasal dari domain yang sama.
    # Jika favicon dari domain yang sama (URL absolut atau relatif), dianggap aman (1).
    # Jika dari domain berbeda atau tidak ditemukan/error, dianggap mencurigakan (-1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    favicon_feature_value = -1
    if soup != -999:
        try:
            favicon_link_tags = soup.find_all(
                'link',
                attrs={'rel': re.compile(r'^(shortcut\s+)?icon$', re.I), 'href': True}
            )
            if favicon_link_tags:
                first_favicon_href = favicon_link_tags[0].get('href')
                if first_favicon_href:
                    parsed_favicon_url = urlparse(first_favicon_href)
                    if parsed_favicon_url.scheme and parsed_favicon_url.netloc:
                        favicon_hostname = parsed_favicon_url.netloc
                        if favicon_hostname.startswith("www."):
                            favicon_hostname = favicon_hostname.replace("www.", "", 1)
                        if domain and favicon_hostname == domain: # Pastikan domain tidak kosong
                            favicon_feature_value = 1
                    else: # Path relatif atau data URI
                        favicon_feature_value = 1
        except Exception as e:
            # print(f"Error processing favicon for {url}: {e}")
            pass # favicon_feature_value tetap -1
    data_set.append(favicon_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Favicon_Source_Consistency: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 10. Custom_Port_Usage
    # Fitur ini memeriksa apakah domain dalam URL menyertakan nomor port secara eksplisit.
    # Jika port disebutkan (misal, 'example.com:8080'), dianggap mencurigakan (-1).
    # Jika tidak ada port eksplisit, dianggap aman (1).
    # Catatan: 'domain' di sini adalah hasil ekstraksi dari URL, mungkin sudah tanpa port
    # Lebih baik periksa netloc dari URL asli.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    port_feature_value = 1 # Default aman
    try:
        parsed_url_for_port_check = urlparse(current_url)
        if parsed_url_for_port_check.port: # port akan None jika tidak ada, atau integer jika ada
            # Port standar (80 untuk http, 443 untuk https) mungkin tidak selalu eksplisit.
            # Phishing sering menggunakan port non-standar secara eksplisit.
            # Jika port eksplisit ADA, kita tandai.
            # Logika asli hanya ":" in domain yang kurang robus.
            port_feature_value = -1
    except ValueError: # Jika port tidak valid (misal, "domain:abc")
        port_feature_value = -1
    except Exception:
        port_feature_value = -1 # Error lain, anggap mencurigakan
    data_set.append(port_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Custom_Port_Usage: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 11.External_Resource_Ratio
    # Fitur ini menganalisis persentase sumber daya eksternal (gambar, skrip, dll.) pada halaman.
    # <22% sumber daya dari domain yang sama: -1 (sangat mencurigakan).
    # 22% - <61% dari domain yang sama: 0 (mencurigakan/normal).
    # >=61% dari domain yang sama: 1 (aman).
    # Jika halaman gagal dimuat atau tidak ada sumber daya, dianggap -1 atau 1 tergantung implementasi.

    start_time = time.time() # Mulai timer untuk pengukuran waktu
    num_total_resources = 0
    num_same_domain_resources = 0
    request_url_feature_value = 1 # Default aman jika tidak ada resource/gagal parse

    if soup == -999:
        request_url_feature_value = -1
    else:
        all_resource_elements = []
        src_based_tags = ['img', 'script', 'iframe', 'embed', 'audio', 'video', 'source', 'track', 'frame']
        for tag_name in src_based_tags:
            all_resource_elements.extend(soup.find_all(tag_name, src=True))
        all_resource_elements.extend(soup.find_all('object', data=True))
        all_resource_elements.extend(soup.find_all('input', type='image', src=True))
        all_resource_elements.extend(soup.find_all('link', rel='stylesheet', href=True))

        for tag_object in all_resource_elements:
            resource_url_str = None
            if tag_object.name == 'object':
                resource_url_str = tag_object.get('data')
            elif tag_object.name == 'link':
                resource_url_str = tag_object.get('href')
            else:
                resource_url_str = tag_object.get('src')

            if not resource_url_str:
                continue

            num_total_resources += 1
            is_same_domain = False
            parsed_resource_url = urlparse(resource_url_str)

            if parsed_resource_url.scheme and parsed_resource_url.netloc:
                resource_hostname = parsed_resource_url.netloc
                if resource_hostname.startswith("www."):
                    resource_hostname = resource_hostname.replace("www.", "", 1)
                if domain and resource_hostname == domain: # Pastikan domain tidak kosong
                    is_same_domain = True
            else: # URL Relatif atau Data URI
                is_same_domain = True

            if is_same_domain:
                num_same_domain_resources += 1

        if num_total_resources > 0:
            percent_same_domain = (num_same_domain_resources / float(num_total_resources)) * 100
            if percent_same_domain < 40.0:
                request_url_feature_value = -1
            else: # >= 61.0
                request_url_feature_value = 1
        # else: request_url_feature_value tetap 1 (default jika tidak ada resources)
    # data_set.append(request_url_feature_value)
    # Masukkan persentase sumber daya eksternal sebagai fitur
    data_set.append(num_same_domain_resources / float(num_total_resources) * 100 if num_total_resources > 0 else 100) # Tambahkan persentase sumber daya eksternal sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur External_Resource_Ratio: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 12.External_Links_Ratio
    # Fitur ini menganalisis persentase tautan (<a> tag) yang tidak aman atau eksternal.
    # Tautan dianggap tidak aman jika kosong, '#', 'javascript:', 'mailto:', atau mengarah ke domain eksternal.
    # <31% tautan tidak aman: 1 (aman).
    # 31% - <67% tautan tidak aman: 0 (normal/mencurigakan).
    # >=67% tautan tidak aman: -1 (mencurigakan).
    # Jika tidak ada tautan, dianggap aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    num_total_anchors = 0
    num_unsafe_anchors = 0
    anchor_feature_value = 1 # Default aman

    if soup == -999:
        anchor_feature_value = -1
    else:
        for a_tag in soup.find_all('a', href=True):
            num_total_anchors += 1
            is_anchor_unsafe = False
            anchor_href = a_tag.get('href', '').strip()
            anchor_href_lower = anchor_href.lower()

            if not anchor_href or \
               anchor_href_lower.startswith('#') or \
               anchor_href_lower.startswith('javascript:') or \
               anchor_href_lower.startswith('mailto:'):
                is_anchor_unsafe = True
            else:
                parsed_anchor_url = urlparse(anchor_href)
                if parsed_anchor_url.scheme.lower() in ['http', 'https'] and parsed_anchor_url.netloc:
                    anchor_hostname = parsed_anchor_url.netloc
                    if anchor_hostname.startswith("www."):
                        anchor_hostname = anchor_hostname.replace("www.", "", 1)
                    if domain and anchor_hostname != domain: # Pastikan domain tidak kosong
                        is_anchor_unsafe = True
            if is_anchor_unsafe:
                num_unsafe_anchors += 1

        if num_total_anchors > 0:
            percentage_unsafe_anchors = (num_unsafe_anchors / float(num_total_anchors)) * 100
            if percentage_unsafe_anchors < 50.0:
                anchor_feature_value = 1
            else:
                anchor_feature_value = -1
    #data_set.append(anchor_feature_value)
    # Masukkan persentase tautan tidak aman sebagai fitur
    data_set.append(num_unsafe_anchors / float(num_total_anchors) * 100 if num_total_anchors > 0 else 100) # Tambahkan persentase tautan tidak aman sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur External_Links_Ratio: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 13.External_CSS_and_JS_Resources
    # Fitur ini menganalisis persentase tautan di tag <link rel="stylesheet"> dan <script src="...">
    # yang berasal dari domain yang sama.
    # <17% dari domain sama: -1 (sangat mencurigakan).
    # 17% - <81% dari domain sama: 0 (normal).
    # >=81% dari domain sama: 1 (aman).
    # Jika tidak ada link/script atau gagal parse, nilai default (1 atau -1) diterapkan.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    num_total_links_scripts = 0
    num_same_domain_links_scripts = 0
    links_in_tags_feature_value = 1 # Default aman

    if soup == -999:
        links_in_tags_feature_value = -1
    else:
        # Analisis tag <link rel="stylesheet" href="...">
        for link_tag in soup.find_all('link', rel='stylesheet', href=True):
            num_total_links_scripts += 1
            resource_url_str = link_tag.get('href')
            if not resource_url_str: continue
            is_same_domain = False
            parsed_resource_url = urlparse(resource_url_str)
            if parsed_resource_url.scheme and parsed_resource_url.netloc:
                resource_hostname = parsed_resource_url.netloc
                if resource_hostname.startswith("www."): resource_hostname = resource_hostname.replace("www.", "", 1)
                if domain and resource_hostname == domain: is_same_domain = True # Pastikan domain tidak kosong
            else: is_same_domain = True
            if is_same_domain: num_same_domain_links_scripts += 1

        # Analisis tag <script src="...">
        for script_tag in soup.find_all('script', src=True):
            num_total_links_scripts += 1
            resource_url_str = script_tag.get('src')
            if not resource_url_str: continue
            is_same_domain = False
            parsed_resource_url = urlparse(resource_url_str)
            if parsed_resource_url.scheme and parsed_resource_url.netloc:
                resource_hostname = parsed_resource_url.netloc
                if resource_hostname.startswith("www."): resource_hostname = resource_hostname.replace("www.", "", 1)
                if domain and resource_hostname == domain: is_same_domain = True # Pastikan domain tidak kosong
            else: is_same_domain = True
            if is_same_domain: num_same_domain_links_scripts += 1

        if num_total_links_scripts > 0:
            percentage_same_domain = (num_same_domain_links_scripts / float(num_total_links_scripts)) * 100
            if percentage_same_domain < 50.0:
                links_in_tags_feature_value = -1
            else: 
                links_in_tags_feature_value = 1
    # data_set.append(links_in_tags_feature_value)
    # Masukkan persentase tautan di tag <link rel="stylesheet"> dan <script src="..."> sebagai fitur
    data_set.append(num_same_domain_links_scripts / float(num_total_links_scripts) * 100 if num_total_links_scripts > 0 else 100) # Tambahkan persentase tautan di tag <link rel="stylesheet"> dan <script src="..."> sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur External_CSS_and_JS_Resources: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 14.External_Form_Submission
    # Fitur ini memeriksa atribut 'action' pada tag <form>.
    # Jika action kosong atau "about:blank", dianggap sangat mencurigakan (-1).
    # Jika action mengarah ke domain eksternal, dianggap mencurigakan/normal (0).
    # Jika action ke domain yang sama atau path relatif (aman), atau tidak ada form, dianggap aman (1).
    # Hanya form pertama yang dianalisis jika ada banyak.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    sfh_feature_value = 1 # Default aman
    if soup == -999:
        sfh_feature_value = -1
    else:
        forms_with_action = soup.find_all('form', action=True)
        action_processed = False
        if forms_with_action: # Hanya proses jika ada form dengan action
            for form_tag in forms_with_action: # Loop, tapi hanya akan break setelah yang pertama
                action_attribute = form_tag.get('action', '').strip()
                if not action_attribute or action_attribute.lower() == "about:blank":
                    sfh_feature_value = -1
                else:
                    parsed_action_url = urlparse(action_attribute)
                    if parsed_action_url.scheme.lower() in ['http', 'https'] and parsed_action_url.netloc:
                        action_hostname = parsed_action_url.netloc
                        if action_hostname.startswith("www."):
                            action_hostname = action_hostname.replace("www.", "", 1)
                        if domain and action_hostname != domain: # Pastikan domain tidak kosong
                            sfh_feature_value = 0
                        # else: sfh_feature_value tetap 1 (aman, ke domain sama)
                    # else: (path relatif atau skema lain) sfh_feature_value tetap 1 (aman)
                action_processed = True
                break # Hanya proses form pertama yang ditemukan dengan atribut action
        # Jika tidak ada forms_with_action, sfh_feature_value tetap 1 (aman)
    data_set.append(sfh_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur External_Form_Submission: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 15.Form_Submits_to_Email_Address
    # Fitur ini memeriksa apakah ada form yang mengirim data ke alamat email (action="mailto:...").
    # Jika ya, dianggap sangat mencurigakan (-1). Jika tidak atau halaman gagal dimuat, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    submission_to_email_feature_value = 1
    if response == "" or soup == -999: # response string kosong jika get gagal, soup -999 jika parse gagal
        submission_to_email_feature_value = -1 # Gagal memuat/parse halaman, anggap mencurigakan
    else: # soup valid
        form_submits_to_email = False
        for form_tag in soup.find_all('form', action=True):
            action_attribute = form_tag.get('action', '').strip().lower()
            if action_attribute.startswith('mailto:'):
                form_submits_to_email = True
                break
        if form_submits_to_email:
            submission_to_email_feature_value = -1
    data_set.append(submission_to_email_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Form_Submits_to_Email_Address: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 16.HTTP_Response_Status
    # Fitur ini memeriksa apakah ada konten di halaman respons.
    # Jika permintaan gagal (response=""), dianggap sangat mencurigakan (-1).
    # Jika halaman kosong (response.text=""), dianggap normal/mencurigakan (0).
    # Jika halaman memiliki konten, dianggap aman (1).
    # Catatan: WHOIS response tidak relevan untuk fitur ini.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    page_content_feature_value = 0 # Default ke netral/mencurigakan
    if response == "": # String kosong menandakan kegagalan request awal
        page_content_feature_value = -1
    elif hasattr(response, 'text'): # Pastikan response adalah objek response yang valid
        if response.text == "":
             # Halaman kosong. Bisa jadi normal (204 No Content) atau mencurigakan.
            page_content_feature_value = 0
        else:
            # Halaman memiliki konten.
            page_content_feature_value = 1
    else: # Jika response bukan objek yang diharapkan (misal int -999 dari kegagalan sebelumnya)
        page_content_feature_value = -1 # Anggap mencurigakan jika struktur response tidak sesuai
    data_set.append(page_content_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur HTTP_Response_Status: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 17.Number_of_Redirects
    # Fitur ini menghitung jumlah redirect yang terjadi saat mengakses URL.
    # 0-1 redirect: 1 (aman).
    # 2-4 redirect: 0 (normal/mencurigakan).
    # >4 redirect: -1 (mencurigakan/berbahaya).
    # Jika gagal memuat, dianggap -1.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    redirect_feature_value = -1 # Default mencurigakan
    if response == "": # Gagal memuat awal
        redirect_feature_value = -1
    elif hasattr(response, 'history'): # Pastikan response adalah objek dari requests
        num_redirects = len(response.history)
        if num_redirects <= 1:
            redirect_feature_value = 1
        elif num_redirects >= 2 and num_redirects <= 4:
            redirect_feature_value = 0
        else: # num_redirects > 4
            redirect_feature_value = -1
    # else: redirect_feature_value tetap -1 jika response tidak punya atribut history
    # data_set.append(redirect_feature_value)
    # Masukkan jumlah redirect sebagai fitur
    data_set.append(len(response.history) if hasattr(response, 'history') else -1) # Tambahkan jumlah redirect sebagai fitur
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Number_of_Redirects: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 18.Mouseover_Link_Manipulation
    # Fitur ini memeriksa keberadaan event "onmouseover" di konten halaman.
    # Penggunaan "onmouseover" (sering untuk menyembunyikan URL asli di status bar) dianggap mencurigakan (-1).
    # Jika tidak ada atau halaman gagal dimuat, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    on_mouseover_feature_value = 1
    if response == "" or soup == -999:
        on_mouseover_feature_value = -1 # Gagal memuat/parse, anggap mencurigakan
    elif hasattr(response, 'text'): # Pastikan response.text ada
        if re.search(r"onmouseover", response.text, re.IGNORECASE):
            on_mouseover_feature_value = -1
    # else: on_mouseover_feature_value tetap 1 jika response.text tidak ada (misal response bukan objek valid)
    data_set.append(on_mouseover_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Mouseover_Link_Manipulation: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 19.Right_Click_Disabled
    # Fitur ini memeriksa apakah ada upaya untuk menonaktifkan klik kanan.
    # Jika ditemukan kode penonaktifan klik kanan (misal, 'oncontextmenu', 'event.button==2'),
    # dianggap mencurigakan (-1). Jika tidak atau gagal muat, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    disable_right_click_feature_value = 1
    if response == "" or soup == -999:
        disable_right_click_feature_value = -1
    elif hasattr(response, 'text'):
        if re.search(r"oncontextmenu|event\.button\s*==\s*2|event\.which\s*==\s*3", response.text, re.IGNORECASE):
            disable_right_click_feature_value = -1
    data_set.append(disable_right_click_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Right_Click_Disabled: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 20.Popup_Window_Usage
    # Fitur ini memeriksa keberadaan kode JavaScript yang membuat pop-up atau dialog (alert, confirm, prompt, window.open).
    # Jika ditemukan, dianggap mencurigakan (-1). Jika tidak atau gagal muat, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    popup_window_feature_value = 1
    if response == "" or soup == -999:
        popup_window_feature_value = -1
    elif hasattr(response, 'text'):
        if re.search(r"alert\s*\(|confirm\s*\(|prompt\s*\(|window\.open\s*\(", response.text, re.IGNORECASE):
            popup_window_feature_value = -1
    data_set.append(popup_window_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Popup_Window_Usage: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 21.Iframe_Usage
    # Fitur ini memeriksa keberadaan tag <iframe> atau <frame>.
    # Penggunaan iframe/frame dianggap mencurigakan (-1). Jika tidak ada atau gagal muat/parse, aman (1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    iframe_feature_value = 1
    if response == "" or soup == -999:
        iframe_feature_value = -1
    elif soup != -999 : # Pastikan soup bukan placeholder error
        if soup.find("iframe") or soup.find("frame"):
            iframe_feature_value = -1
    data_set.append(iframe_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Iframe_Usage: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 22.Domain_Age
    # Fitur ini memeriksa usia domain berdasarkan tanggal pembuatan dari data WHOIS.
    # Usia >= 6 bulan: 1 (aman).
    # Usia < 6 bulan atau tidak bisa ditentukan: -1 (mencurigakan).
    def to_aware_utc(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    start_time = time.time()
    domain_age_feature_value = -1
    actual_creation_date = None

    if whois_response and hasattr(whois_response, 'creation_date'):
        creation_date_data = whois_response.creation_date

        if isinstance(creation_date_data, list):
            aware_dates = [to_aware_utc(d) for d in creation_date_data if isinstance(d, datetime)]
            if aware_dates:
                actual_creation_date = min(aware_dates)
        elif isinstance(creation_date_data, datetime):
            actual_creation_date = to_aware_utc(creation_date_data)

    current_time = datetime.now(timezone.utc)

    try:
        if actual_creation_date:
            age_months = diff_month(current_time, actual_creation_date)
            if age_months >= 6:
                domain_age_feature_value = 1
            else:
                domain_age_feature_value = -1
        else:
            domain_age_feature_value = -1
    except Exception as e:
        print("Error calculating domain age:", e)
        domain_age_feature_value = -1

    data_set.append(diff_month(current_time, actual_creation_date) if actual_creation_date else -1)

    end_time = time.time()
    print(f"Waktu eksekusi untuk fitur Domain_Age: {end_time - start_time:.4f} detik")


    # 23.Whois_Data_Availability_and_Expiry
    # Fitur ini menilai berdasarkan ketersediaan record DNS (via WHOIS lookup) dan sisa masa aktif domain.
    # Jika WHOIS lookup gagal (dns=-1), dianggap mencurigakan (-1).
    # Jika WHOIS berhasil tapi sisa masa aktif <= 1 tahun, dianggap mencurigakan (-1).
    # Jika WHOIS berhasil dan sisa masa aktif > 1 tahun, dianggap aman (1).
    # Variabel 'registration_length_days' sudah dihitung di fitur #8.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    dns_record_feature = -1 # Default mencurigakan
    # Cek apakah whois_response (hasil dari whois.whois()) ada dan bukan error
    if whois_response and whois_response.domain_name: # .domain_name adalah salah satu field yang biasanya ada jika WHOIS berhasil
        # WHOIS lookup dianggap berhasil. Sekarang cek 'registration_length_days'.
        # 'registration_length_days' dihitung di fitur #8.
        # Jika whois_expiration_date_val adalah None atau list kosong di fitur #8,
        # maka registration_length_days akan tetap 0 atau menjadi nilai dari perhitungan yang mungkin salah.
        # Kita perlu memastikan logika di fitur #8 robust atau re-evaluasi di sini.
        # Menggunakan nilai 'domain_reg_len_feature' dari fitur #8 bisa lebih langsung.
        if domain_reg_len_feature == 1: # Jika fitur #8 menganggapnya aman (masa aktif > 1 tahun)
             dns_record_feature = 1
        else: # Jika fitur #8 menganggapnya mencurigakan (masa aktif <= 1 tahun atau error)
             dns_record_feature = -1
    else: # WHOIS lookup gagal atau tidak menghasilkan data yang diharapkan
        dns_record_feature = -1
    data_set.append(dns_record_feature)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur Whois_Data_Availability_and_Expiry: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi
    
    # 24.URL_Blacklist_Status
    # Fitur ini memeriksa apakah URL atau alamat IP domain ada dalam daftar blokir (suspicious patterns).
    # JikaA URL atau IP-nya ada di daftar, dianggap mencurigakan (-1).
    # Jika tidak, atau jika resolusi DNS gagal, aman (1) atau mencurigakan (-1) tergantung kasus.
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    suspicious_url_patterns = r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly'
    suspicious_ip_patterns = (
        r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42'
    )
    blocklist_feature_value = 1 # Default aman
    if re.search(suspicious_url_patterns, current_url): # Periksa URL lengkap
        blocklist_feature_value = -1
    elif domain: # Hanya lakukan lookup IP jika domain ada
        try:
            ip_address_str = socket.gethostbyname(domain)
            if re.search(suspicious_ip_patterns, ip_address_str):
                blocklist_feature_value = -1
        except socket.gaierror:
            # print(f"DNS resolution failed for domain {domain}")
            blocklist_feature_value = -1 # Gagal resolusi DNS, anggap mencurigakan
        except Exception as e:
            # print(f"Error resolving IP for domain {domain}: {e}")
            blocklist_feature_value = -1 # Error lain, anggap mencurigakan
    elif not domain: # Jika domain tidak bisa diekstrak dari URL
        blocklist_feature_value = -1 # URL mungkin sudah aneh, anggap mencurigakan
    data_set.append(blocklist_feature_value)
    end_time = time.time() # Akhiri timer
    print(f"Waktu eksekusi untuk fitur URL_Blacklist_Status: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi

    # 25.Domain_Registration_Entity
    # Fitur ini memeriksa apakah domain terdaftar atas nama organisasi (bukan individu atau layanan privasi).
    # Jika ada nama organisasi yang valid di WHOIS dan bukan layanan privasi, dianggap aman (1).
    # Jika tidak ada, kosong, atau terindikasi layanan privasi, dianggap mencurigakan (-1).
    start_time = time.time() # Mulai timer untuk pengukuran waktu
    domain_registered_by_company_value = -1
    if whois_response:
        try:
            # Nama field bisa 'org', 'organization', 'registrant_organization', dll.
            # Coba beberapa yang umum atau yang dikembalikan oleh pustaka Anda.
            registrant_organization = whois_response.get('org') or \
                                      whois_response.get('organization') or \
                                      getattr(whois_response, 'org', None) or \
                                      getattr(whois_response, 'organization', None)


            if registrant_organization and isinstance(registrant_organization, str) and registrant_organization.strip():
                known_privacy_phrases = ["privacy", "proxy", "whoisguard", "domains by proxy", "contact privacy", "private registration", "redacted for privacy"]
                is_privacy_service = False
                org_lower = registrant_organization.lower()
                for phrase in known_privacy_phrases:
                    if phrase in org_lower:
                        is_privacy_service = True
                        break
                if is_privacy_service:
                    domain_registered_by_company_value = -1
                else:
                    domain_registered_by_company_value = 1
            # else: 'org' tidak ada atau kosong, domain_registered_by_company_value tetap -1
        except AttributeError: # Jika atribut seperti .org tidak ada
            domain_registered_by_company_value = -1
        except Exception as e:
            # print(f"Error processing company registration for {domain}: {e}")
            domain_registered_by_company_value = -1 # Error, anggap mencurigakan
    # else: whois_response adalah None, domain_registered_by_company_value tetap -1
    data_set.append(domain_registered_by_company_value)
    end_time = time.time() # Akhiri timerw
    print(f"Waktu eksekusi untuk fitur Domain_Registration_Entity: {end_time - start_time:.4f} detik") # Cetak waktu eksekusi
    logger.info(f"Selesai ekstraksi fitur untuk URL: {current_url}. Total fitur: {len(data_set)}")

    print(f"Waktu total eksekusi untuk semua fitur: {time.time() - start_all:.4f} detik") # Cetak waktu total eksekusi
    return data_set