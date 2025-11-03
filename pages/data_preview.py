import pandas as pd
import streamlit as st

import io




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




def gruplama_yap_ve_analiz_et(df):

    st.write("---")
    st.title("📊 Veri Gruplama")
    st.write("---")

    kolonlar = df.columns.tolist() # dataframe'in içindeki tüm kolon isimlerini alır ve bunları bi liste olarak kaydedediyoruz (selectbox ta liste olarak parametre veriyoruz).

    # kullanıcının bu seçeneklerden bir sütun seçmesi isteniyor.
    gruplama_sutunu = st.selectbox(
        "Lütfen gruplama yapmak istediğiniz sütunu seçin:",
        options=["Seçim yapın"] + kolonlar
    )


    if gruplama_sutunu != "Seçim yapın":

        try:

            # Seçilen sütuna göre gruplama yap ve sayısal sütunların özetini çıkar
            gruplu_veri = df.groupby(gruplama_sutunu).agg(['count', 'mean', 'sum']).reset_index()

        # bu, dataframe'i (df) belirtilen sütundaki (gruplama_sutunu) değerlere göre gruplara ayırıyoruz.
        # gruplanmış her bir veri grubu üzerindeki sayısal sütunlara ayrı ayrı belirtilen toplama (aggregation) fonksiyonlarını uyguluyoruz.
        # gruplama işlemini yaptıktan sonra varsayılan olarak indeks haline gelen gruplama_sutunu'nu tekrar normal bir sütun haline getiriyoruz.


            st.write(f"**'{gruplama_sutunu}'** Sütununa Göre Gruplanmış Verilerin Özeti:")
            st.dataframe(gruplu_veri)

        except Exception as e:
            st.error(f"Gruplama işlemi sırasında bir hata oluştu: {e}")
            st.info("Sadece sayısal veriler gruplanabilir. Lütfen farklı bir sütun seçin.")






def eksik_degerleri_doldur_ve_indir(df, dosya_adi):


    st.write("---")
    st.title("📝 Eksik Değerleri Doldur")
    st.write("---")

    # bu satırda amaçladığımız boş hücre içeren sütunları bulmak
    bos_hucre_sutunlari = df.columns[df.isnull().any()].tolist()
    # burada df.isnull() bir boolean (true-false) dataframe oluşturuyor. hücre boşsa (nan ise) true, doluysa false değerini veriyor.
    # .any() ise elde edilen boolean dataframe'i alır ve her bir sütunda en az bir tane true (yani en az bir boş hücre) olup olmadığını kontrol eder ve bir series oluşturur.
    # .tolist() ise eksik değer içeren sütun isimlerini bir liste haline getiriyoruz ve bos_hucre_sutunlari değişkenine atıyoruz.



    # eğer "bos_hucre_sutunlari" isimli listemiz boşsa
    if not bos_hucre_sutunlari:
        st.info("✅ Dosyada boş hücre bulunmamaktadır.")
        return

    # burada kullanıcayı açılır bir menü,selectbox gösteriyoruz kullanıcı boş hücre bulunan sütunlardan birini seçer
    kolon = st.selectbox(
        "Boş hücreleri doldurmak istediğiniz sütunu seçin:",
        options=bos_hucre_sutunlari
    )

    # burada kullanıcıya boş hücreleri doldurması için  3 klasik seçenek sunuyoruz
    doldurma_yontemi = st.radio(
        "Doldurma Yöntemi:",
        ("Ortalama ile doldur", "Medyan ile doldur", "Belirli bir değer ile doldur")
    )



    # burda doldurulacak_deger değişkeni none , bir doldurma yöntemi seçilmezse bir değer atanmamış olur
    doldurulacak_deger = None

    # eğer kullanıcı ortalama ile doldur seçeneğini seçerse bu blok çalışıcak.
    if doldurma_yontemi == "Ortalama ile doldur":

        if pd.api.types.is_numeric_dtype(df[kolon]): # burada true - false şeklinde bir sonuç çıkacak ---> seçilen sütunun sayısal bir veri tipi (integer,float) olup olmadığını kontrol eder sayısal ise true der ve if blok içine girer değilse false else blok içine girer.
            doldurulacak_deger = df[kolon].mean() # seçilen sütunun ortalamasını alır
            st.info(f"Boş hücreler, '{kolon}' sütununun ortalaması olan **{doldurulacak_deger:.2f}** ile doldurulacak.")
        else:
            st.warning("Seçilen sütun sayısal değil, ortalama ile doldurma uygulanamaz.")
            return


    # eğer kullanıcı Medyan ile doldur seçeneğini seçerse bu blok çalışıcak.
    elif doldurma_yontemi == "Medyan ile doldur":

        if pd.api.types.is_numeric_dtype(df[kolon]):
            doldurulacak_deger = df[kolon].median()
            st.info(f"Boş hücreler, '{kolon}' sütununun medyanı olan **{doldurulacak_deger:.2f}** ile doldurulacak.")
        else:
            st.warning("Seçilen sütun sayısal değil, medyan ile doldurma uygulanamaz.")
            return


    # eğer kullanıcı Belirli bir değer ile doldur seçeneğini seçerse bu blok çalışıcak.
    elif doldurma_yontemi == "Belirli bir değer ile doldur":

        doldurulacak_deger = st.text_input("Lütfen boş hücreleri doldurmak için bir değer girin:")
        if not doldurulacak_deger: # kullanıcı bir değer girmesse
            return # fonksiyon durdurulur




    # şimdi burada eksik değerleri doldur butonuna tıklanırsa
    if st.button("Eksik Değerleri Doldur"):
        # orijinal bulunan dataframe'in bir kopyasını oluşturarak işlem yapıyoruz orijinali korumak , zarar vermemek için
        df_guncel = df.copy()

        try:
            # eğer kullanıcı belirli bir değer ile doldur seçeneğini seçtiyse bizim text_input tan aldığımız değer o sütunun hedef sütunun veri tipine uygun hale getirmeye çalışıyoruz.
            if doldurma_yontemi == "Belirli bir değer ile doldur":
                if pd.api.types.is_numeric_dtype(df_guncel[kolon]): # eğer kolon sayısal bir veri tipindeyse (boş hücrelerini dolduracağımız kolon)
                    doldurulacak_deger = pd.to_numeric(doldurulacak_deger)  # gelen değeri sayısal veri tipine dönüştürüyor
                else:
                    doldurulacak_deger = str(doldurulacak_deger) # sayısal değilse string veri tipine dönüştürüyor

            df_guncel[kolon] = df_guncel[kolon].fillna(doldurulacak_deger) # .fillna() metodu ile doldurma işlemi gerçekleştiriliyor
            st.session_state["veri"] = df_guncel # df guncel dosyamız session_state içine kaydedilerek artık bu dosya ile çalışılması sağlanıyor
            st.success("✅ Eksik değerler başarıyla dolduruldu!")

        # try bloğu içerisinde hata oluşması sonucu çalışır
        except ValueError:
            st.error("Girdiğiniz değer, seçilen sütunun veri tipiyle uyumlu değil.")


        # ---> bu kısım dosya indirme işlemini ayarladığımız kısmımız

        if "veri" in st.session_state:
            st.write("---")
            st.subheader("📥 Dosyayı İndir")


            uzanti = dosya_adi.split('.')[-1] # burada yüklediğimiz orijinal dosyanın uzantısını kontrol ediyoruz(csv mi xlsx mi)
                                # burada dosya adını nokta karakterinde ayırıyor ve bir liste oluşturuyor , sonrada bu listesin son elamanını alyor ve bunu uzantı değişkenimize atıyoruz
                                    # mesela dosya adı "verilerim.xlsx"  noktadan ayırıyor liste oluşturuyor----> ["verilerim","xlsx"] ---> burada tersten index okursak -1 den başlıyor bizde onu alıyoruz

            # eğer dosya uzantımız csv ise to_csv() ile UTF-8 kodlamasında hazırlanıyor
            if uzanti == 'csv':
                cikti = st.session_state["veri"].to_csv(index=False).encode('utf-8')
                mime_type = 'text/csv'  # mime type burada text-csv yani metin/virgülle ayrılmış değerler, ---> tarayıcıya dosyanın türünü bildiren kimlik kartıdır.
                indirme_adi = f"guncellenmis_{dosya_adi}"

            # eğer dosya uzantımız xlsx ise io.BytesIO kullanılarak excel formatında bellek içinde hazırlanır.bu streamlit'e excel verisini indirme yeteneği kazandırmak için gereken python yöntemidir
            elif uzanti == 'xlsx':

                excel_cikti = io.BytesIO()
                st.session_state["veri"].to_excel(excel_cikti, index=False)
                excel_cikti.seek(0) # io.BytesIO ile bir dosya oluşturulduğunda, veriyi yazma işlemi imleci dosyanın sonuna taşıyor seek(0) ile İmleci 0.(sıfırıncı) pozisyona (yani dosyanın başlangıcına) geri taşıyoruz.
                                                        # ---> Eğer bu yapılmazsa, bir sonraki okuma/alma (.getvalue()) komutu dosyanın sonundan başlar ve boş bir dosya veya eksik veri indirilir.

                cikti = excel_cikti.getvalue()  # burada bellekte oluşturulan excel verisini (BytesIO nesnesi) streamlit in st.download_button'una verebileceğimiz formata dönüştürüyor yani ---> uygun olan ham bayt dizisi (bytes) formatına dönüştürüyor.
                mime_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'  # mime type, tarayıcıya dosyanın türünü bildiren kimlik kartıdır. burada mıme type değişkenine yazdığımız atadığımız ise ---> tarayıcının indirdiği dosyanın bir Excel (2007 ve sonrası) belgesi olduğunu anlamasını sağlayan resmi ve uzun mime tipidir.
                indirme_adi = f"guncellenmis_{dosya_adi}"

            else:

                return

            # hazırlanan verimiz(data=cikti) belirlenen dosya adı ve mime_type ile birlikte kullanıcıya sunulur , butona tıklandığında tarayıcı dosyayı kullanıcın diskine indirir
            st.download_button(
                label="Güncellenmiş Dosyayı İndir",
                data=cikti,
                file_name=indirme_adi,
                mime=mime_type # dosya sunucularında ve tarayıcılarda dosya türünü tanımlamak için mıme type ı kullanıyoruz
            )
            st.info("Dosyayı indirmek için yukarıdaki butona tıklayın.")





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



# Eğer session_state te bir veri varsa onu placeholder da göster
if "veri" in st.session_state and st.session_state["veri"] is not None:

    #"veri" in st.session_state → bu kısım oturumda "veri" anahtarı var mı?
    #st.session_state["veri"] is not None →  bu kısım ise varsa, değeri boş mu değil mi?
    
    # bunu kontrol eder eğer her iki koşul da True ise veri_ayiklama_ve_gosterim fonksiyonu çağrılır
    # Bu sayede yalnızca veri başarıyla yüklendiğinde fonksiyonumuz çalıştırılır.
     



    # Eski içeriği silmek ve yeni içeriği yerleştirmek için placeholderı kullanıyoruz.

    veri_ayiklama_ve_gosterim(placeholder, st.session_state["veri"], st.session_state["dosya_adi"])  # veri_ayiklama_ve_gosterim fonksiyonunu çağırıyoruz

    gruplama_yap_ve_analiz_et(st.session_state["veri"])

    eksik_degerleri_doldur_ve_indir(st.session_state["veri"], st.session_state["dosya_adi"])  # eksik_degerleri_doldur_ve_indir fonksiyonunu çağırıyoruz


else:
    # Placeholderı temizleme
    placeholder.empty()
    st.info("⬆️ Lütfen bir dosya yükleyin .")


st.write("---")
