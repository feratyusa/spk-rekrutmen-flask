# Backend Sistem Pendukung Keputusan Rekrutmen Karyawan

Aplikasi ini dibangun untuk Tugas Akhir Teknik Informatika ITS

Teknologi: Flask

## Cara Penggunaan

1. Install dependency yang diperlukan dengan menjalankan `pip install -r requirements.txt`.\
(disarankan untuk menggunakan Virtual Environments [venv](https://docs.python.org/3/library/venv.html))

2. Konfigurasi file `.env` (jika belum ada maka dibuat terlebih dahulu) dengan isi sebagai berikut:

    ```(env)
    DATABASE_URL=[url_database]
    SECRET_KEY_JWT=[random_string]
    ```

3. Jalankan aplikasi dengan command `flask run`

## Catatan

- Metode SAW dan AHP dapat dilihat pada folder `method`
- Kedua metode dapat dicoba secara manual dan cara penggunaan dapat melihat comment pada `saw.py` dan `ahp.py`

Frontend Aplikasi: [SPK Frontend](https://github.com/feratyusa/spk-rekrutmen-react)
