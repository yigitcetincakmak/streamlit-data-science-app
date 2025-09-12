import pandas as pd
import streamlit as st


import psycopg2
import json
from datetime import datetime


# https://docs.streamlit.io/


try:

    conn = psycopg2.connect(
        host="localhost",
        dbname="streamlitdb",
        user="postgres",
        password="9831431797",
        port="5432"
    )
    cur = conn.cursor()

except psycopg2.Error as e:

    st.error(f"❌ Veritabanı bağlantı hatası: {e}")
    st.stop()


def veri_ayiklama_ve_gosterim(placeholder, df, dosya_adi):     # Bu fonksiyon artık içeriği kendisine iletilen placeholder ın içine yazar.

    with placeholder.container():

        st.write("---")
        st.write("🔍 Dosyada Bulunan İlk 10 Satır Gösterimi:")
        st.dataframe(df.head(10))
        st.write("---")

        kolonlar = df.columns
        st.write("Dosyada Bulunan Sütunlar: ")

        j = 1
        for i in kolonlar:

            st.write(j, " ", i.capitalize())
            j += 1
        st.write("---")

        boyut = df.shape

        st.write("✅ Dosyada Bulunan Satır Sayısı:", boyut[0])
        st.write("✅ Dosyada Bulunan Sütun Sayısı:", boyut[1])
        st.write("---")

        null_degerler = df.isnull().sum()
        null_hucreler = null_degerler[null_degerler > 0]

        if df.isnull().sum().sum() == 0:

            st.write("✅ Dosyada Bulunan Sütunlarda Boş Hücre Bulunmamaktadır")

        else:

            for kolon_adi, bos_hucre_sayisi in null_hucreler.items():

                st.write(f"⚠️ **{kolon_adi}** Sütununda **:red[{bos_hucre_sayisi}]** Adet Boş Hücre Bulunmaktadır ")

            st.write("---")
            st.write("Sütunlardaki Boş Hücrelerin Tablo Gösterimi:")
            st.dataframe(null_degerler.to_frame(name="Boş Hücre Sayısı"))

        st.write("---")
        st.title("🧮 Sayısal Sütunların Özeti")
        st.write("---")

        sayisal_sutunlar = df.select_dtypes(include=["int64", "float64"])

        if sayisal_sutunlar.empty:

            st.write("Sayısal Sütun Bulunamadı")

        else:

            for kolon in sayisal_sutunlar.columns:

                with st.expander(f"{kolon.upper()}"):

                    ortalama = sayisal_sutunlar[kolon].mean()
                    min_deger = sayisal_sutunlar[kolon].min()
                    max_deger = sayisal_sutunlar[kolon].max()

                    st.write(f"Ortalama: {ortalama:.2f}")
                    st.write(f"Max Değer: {max_deger}")
                    st.write("Maximum Değerin Bulunduğu Satırlar:")
                    st.dataframe(df[df[kolon] == max_deger])
                    st.write(f"Min Değer: {min_deger}")
                    st.write("Minimum Değerin Bulunduğu Satırlar:")
                    st.dataframe(df[df[kolon] == min_deger])


def veritabanina_kaydet(df, dosya_adi):

    # DataFrame i veritabanına kaydetme

    try:
        cur.execute("DELETE FROM user_data WHERE file_name = %s", (dosya_adi,))
        conn.commit()

        for _, row in df.iterrows():

            cur.execute(
                "INSERT INTO user_data (email, file_name, data, upload_time) VALUES (%s, %s, %s, %s)",
                ("kullanici@ornek.com", dosya_adi, json.dumps(row.to_dict()), datetime.now())
            )

        conn.commit()
        st.success("✅ Veriler veritabanına başarıyla kaydedildi!")

    except Exception as e:

        st.error(f"❌ Veritabanına kaydederken hata oluştu: {e}")







st.set_page_config(page_title="Veri Önizleme", page_icon="📋")
st.title("📋 Veri Önizleme")

# Yeni dosya yükleme
dosya = st.file_uploader("📤 Dosyanızı Yükleyiniz", type=["csv", "xlsx"])


# Önceki dosyaları veritabanından getirme , çekme
cur.execute("""
    SELECT DISTINCT ON (file_name) file_name
    FROM user_data
    ORDER BY file_name, upload_time DESC
""")

onceki_dosyalar = [row[0] for row in cur.fetchall()]


secilen_dosya = None

if onceki_dosyalar:


    secim_listesi = ["Bir dosya seçin"] + onceki_dosyalar
    secilen_dosya = st.selectbox("📂 Önceki Dosyalarınız:", secim_listesi)

# Verinin içeriğini görüntülemek için bir placeholder oluşturuyoruz
placeholder = st.empty()


# programı işlettiğimiz , yönettiğimiz kısım

if dosya:

    # yeni bir dosya yüklediğimizde

    try:

        dosya_adi = dosya.name

        if dosya_adi.endswith(".csv"):
            df = pd.read_csv(dosya)

        elif dosya_adi.endswith(".xlsx"):
            df = pd.read_excel(dosya)

        else:
            st.warning("⚠️ Sadece .csv ya da .xlsx Uzantılı Dosyalar Yüklenebilir.")
            st.stop()

        st.success("✅ Dosya başarıyla yüklendi!")
        st.session_state["veri"] = df
        st.session_state["dosya_adi"] = dosya_adi

        veritabanina_kaydet(df, dosya_adi)  # ------ veritabanina_kaydet fonksiyonumuzu çağırıyoruz

    except Exception as e:
        st.error(f"❌ Dosya okunurken hata oluştu: {e}")

elif secilen_dosya and secilen_dosya != "Bir dosya seçin":

    # Önceki bir dosya seçildiğinde

    try:

        cur.execute("SELECT data FROM user_data WHERE file_name = %s", (secilen_dosya,))
        rows = cur.fetchall()
        df_list = [row[0] for row in rows]
        df_selected = pd.DataFrame(df_list)
        st.session_state["veri"] = df_selected
        st.session_state["dosya_adi"] = secilen_dosya


    except Exception as e:

        st.error(f"❌ Veritabanından veri okunurken hata oluştu: {e}")
        st.session_state["veri"] = None
        st.session_state["dosya_adi"] = None


# Eğer session_state te bir veri varsa onu placeholder da göster

if "veri" in st.session_state and st.session_state["veri"] is not None:

    # Eski içeriği silmek ve yeni içeriği yerleştirmek için placeholderı kullanıyoruz.

    veri_ayiklama_ve_gosterim(placeholder, st.session_state["veri"], st.session_state["dosya_adi"])  # veri_ayiklama_ve_gosterim  fonksiyonunu çağırıyoruz

else:
    # Placeholderı temizleme
    placeholder.empty()
    st.info("⬆️ Lütfen bir dosya yükleyin veya yukarıdan bir dosya seçin.")


st.write("---")
