import pandas as pd
import streamlit as st





 # Bu fonksiyonumuz(veri_ayiklama_ve_gosterim), yüklenen veri dosyasını (CSV veya Excel) analiz ederek kullanıcıya özet bilgi sunmayı amaçlıyor.

 # Bu fonksiyon içerisinde şu işlemleri gerçekleştiriyor
 # -----------------------------------------------------
 # 1. İlk 10 satırı bir tablo , dafaFrame şeklinde gösteriyor.
 # 2. Sütun isimlerini ve toplam satır/sütun sayısını belirtiyor.
 # 3. Boş hücre (NaN) bulunan sütunları tespit edip kullanıcıyı bilgilendiriyor.
 # 4. Sayısal sütunlar için ortalama, minimum ve maksimum değerleri hesaplıyor.
 # 5. Min ve max değerlerin bulunduğu satırları detayları ile , sütun verileri ile görüntülüyor.
 
 # Burada kullandığımız placeholder parametresi, Streamlit arayüzünde dinamik olarak veri gösterimi yapılmasını sağlar.
 
 # 💡 placeholder :
 
 # Streamlit’te sayfa üzerindeki alanları dinamik olarak kontrol etme imkanını bizler sağlar.
 # Yani, sayfa yeniden yüklenmeden aynı alan içinde aynı bölge içinde yeni veriler gösterebiliyoruz.
 # kullanıcı yeni bir dosya yüklediğinde eski içeriğin silinip yenisinin aynı bölgede , aynı alanda görüntülenmesine imkan sağlıyor.
 # (Örneğin: bir dosya yükledik bu dosyanın verilerini gördük , dosyayı değiştirdiğimizde tabloyu temizleyip yeni dosyanın verilerini görmemiz sağlanıyor , dinamiklik sağlıyor aslında)


def veri_ayiklama_ve_gosterim(placeholder, df, dosya_adi):

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






# --- Streamlit Arayüzümüz ---

st.set_page_config(page_title="Veri Önizleme", page_icon="📋")
st.title("📋 Veri Önizleme")

# Yeni dosya yükleme
dosya = st.file_uploader("📤 Dosyanızı Yükleyiniz", type=["csv", "xlsx"])

# Verinin içeriğini görüntülemek için bir placeholder oluşturuyoruz
placeholder = st.empty()


# Bu kısım programı işlettiğimiz , yönettiğimiz kısım

if dosya:

    # yeni bir dosya yüklediğimizde
    try:

        dosya_adi = dosya.name

        if dosya_adi.endswith(".csv"): # burada endswith bir stringin belirli bir karakter veya ifadeyle bitip bitmediğini kontrol eden bir fonksiyondur (yani kullanıcı istediğimiz dosya uzantısında veri yüklemiş mi).
            df = pd.read_csv(dosya)

        elif dosya_adi.endswith(".xlsx"):
            df = pd.read_excel(dosya)

        else:
            st.warning("⚠️ Sadece .csv ya da .xlsx Uzantılı Dosyalar Yüklenebilir.")
            st.stop()

        st.success("✅ Dosya başarıyla yüklendi!")
        st.session_state["veri"] = df
        st.session_state["dosya_adi"] = dosya_adi


    except Exception as e:
        st.error(f"❌ Dosya okunurken hata oluştu: {e}")



if "veri" in st.session_state and st.session_state["veri"] is not None:

    #"veri" in st.session_state → bu kısım oturumda "veri" anahtarı var mı?
    #st.session_state["veri"] is not None →  bu kısım ise varsa, değeri boş mu değil mi?
    
    # bunu kontrol eder eğer her iki koşul da True ise veri_ayiklama_ve_gosterim fonksiyonu çağrılır
    # Bu sayede yalnızca veri başarıyla yüklendiğinde fonksiyonumuz çalıştırılır.
     



    # Eski içeriği silmek ve yeni içeriği yerleştirmek için placeholderı kullanıyoruz.

    veri_ayiklama_ve_gosterim(placeholder, st.session_state["veri"], st.session_state["dosya_adi"])  # veri_ayiklama_ve_gosterim fonksiyonunu çağırıyoruz


else:
    # Placeholderı temizleme
    placeholder.empty()
    st.info("⬆️ Lütfen bir dosya yükleyin .")


st.write("---")
