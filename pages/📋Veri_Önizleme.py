import pandas as pd
import streamlit as st

# Streamlit run titanic_app.py
# World Happiness Report >>> kaggle veri seti

# endswith() Nedir? Python'da bir string’in belirli bir karakterle veya metinle bitip bitmediğini kontrol eden bir fonksiyondur.

# https://docs.streamlit.io/develop/api-reference/widgets



st.set_page_config(page_title="Veri Önizleme", page_icon="📋")
st.title("📋 Veri Önizleme")
dosya = st.file_uploader("📤 Dosyanızı Yükleyiniz",type=["csv","xlsx"])




def veriAyıklama(df):
    dosya_Adı = dosya.name
    st.write("Yüklenen Dosya Adı : ", dosya_Adı)
    st.write("🔍 Dosyada Bulunan ilk 10 Satır Gösterimi :")
    st.dataframe(df.head(10))
    kolonlar = df.columns
    "---"

    st.write("Dosyada Bulunan Sütunlar: ")

    j = 1
    for i in kolonlar:
        st.write(j, " ", i.capitalize())
        j += 1

    boyut = df.shape
    boyut_liste = list(boyut)
    "---"
    st.write("✅Dosyada Bulunan Satır Sayısı: ", boyut_liste[0])
    st.write("✅Dosyada Bulunan Sütun Sayısı: ", boyut_liste[1])
    "---"
    null_Değerler = df.isnull().sum()
    null_hücreler = null_Değerler[null_Değerler > 0]

    if df.isnull().sum().sum() == 0:
        st.write("✅Dosyada Bulunan Sütunlarda Boş Hücre Bulunmamaktadır")
    else:
        for kolon_adi, bos_hücre_sayısı in null_hücreler.items():
            st.write(f"⚠️ {kolon_adi} >>>  Sütununda {bos_hücre_sayısı} Adet Boş Hücre Bulunmaktadır ")
        "---"
        st.write("Sütunlarda Bulunan Boş Hücrelerin Tablo Gösterimi: ", null_Değerler)



    "---"
    st.title("🧮 Sayısal Sütunların Özeti")
    "---"
    sayısal_sütunlar = df.select_dtypes(
        include=["int64", "float64"])  # burada sadece sayısal sütunların yer aldığı yeni bir dataFrame elde ettik.

    if sayısal_sütunlar.empty:
        st.write("Sayısal Sütun Bulunamadı")

    else:
        for kolon in sayısal_sütunlar.columns:

          with st.expander(f"{kolon}".upper()):

            ortalama = sayısal_sütunlar[kolon].mean()
            min_Deger = sayısal_sütunlar[kolon].min()
            max_Deger = sayısal_sütunlar[kolon].max()

            st.write(f"Ortalama : {ortalama}")


            st.write(f"Max Değer : {max_Deger}")
            st.write("Maximum Değerin Bulunduğu Satırlar : ")
            st.dataframe(df[df[kolon] == max_Deger])
            st.write(f"Min Değer : {min_Deger}")
            st.write("Minimum Değerin Bulunduğu Satırlar : ")
            st.dataframe(df[df[kolon] == min_Deger])
            "---"



def veriYukle():

  if dosya:

    dosya_Adı = dosya.name
    st.session_state["dosya_Adi"] = dosya.name
    try:
        if dosya_Adı.endswith(".csv"):
            df = pd.read_csv(dosya)
            st.success("✅ csv Başarıyla Yüklenmiştir")
            "---"
            veriAyıklama(df)
            st.session_state["veri"] = df  # ⬅️ veriyi session_state'e kaydediyoruz  (["Anahtar"] = Değer)
            return df


        elif dosya_Adı.endswith(".xlsx"):
            df = pd.read_excel(dosya)
            st.success("✅ xlsx Başarıyla Yüklenmiştir")
            "---"
            veriAyıklama(df)
            st.session_state["veri"] = df  # ⬅️ veriyi session_state'e kaydediyoruz
            return df

        else:
            st.warning("⚠️ .csv yada .xlsx Uzantılı Dosyalar Yüklenebilir ")


    except Exception as e:
        st.error(f"❌ Dosya Okunurken Hata Oluştu : {e} ")



veriYukle()


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  GROUPBY KOMUTUNU UNUTMA


# if df.isna().any().any():
  #  df.dropna(inplace=True)  # Eksik değer içeren satırları sil
   #  print("nan")  # Eksik veri bulunduysa bilgi mesajı ver      bos hücreleri sileyim mi diye sor













