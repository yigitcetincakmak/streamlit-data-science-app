import streamlit as st
from streamlit import session_state
import matplotlib.pyplot as plt
#Histogram

#pasta Grafik

#Pairplot (Seaborn ile)

#Boxplot

#Scatterplot

def grafikCizim(sütun1,sütun2):

    with st.expander("Çubuk Grafik"):
         st.bar_chart(df , x = sütun1 , y = sütun2)

    with st.expander("Çizgi Grafik"):
        st.line_chart(df , x = sütun1 , y = sütun2)

    with st.expander("Alan Grafiği"):
        st.area_chart(df , x = sütun1 , y = sütun2)

    with st.expander("Histogram Grafiği"):
        sutun_Secim = st.selectbox("",options=sayısal_Sütunların_kolonları_Buyuk_Harf,index = None , placeholder="Histogram İçin Sütun Seçiniz")

        plt.figure()  # önce figür başlat
        plt.hist(df[sutun_Secim], bins=20, color='skyblue', edgecolor='black') # color cubuk içi edgecolor cubukların kenar rengi bins de grafiğin altındaki değerler 0-20-40 diye bölünmesi
        plt.xlabel(sutun_Secim)
        plt.ylabel("Frekans")
        plt.title(f"{sutun_Secim} Histogram")
        st.pyplot(plt)

   #  with st.expander("Dağılım Grafiği"):

        '''
        histogram = plt.hist(sutun_Secim)
        st.pyplot()
        '''


st.title("📊 Veri Görselleştirme")
try:

    if "veri" in session_state:

        df = st.session_state["veri"]
        st.success("✅Dosyanız Başaryla Yüklenmiştir")

        "---"

        dosya_Adi = st.session_state.get("dosya_Adi" , "Bilinmeyen_Dosya")

        st.write("Yüklenen Dosya : " , dosya_Adi)

        "---"
        sayısal_Sütunlar = df.select_dtypes(include=["int64", "float64"])
        sayısal_Sütunların_kolonları = list(sayısal_Sütunlar.columns)

        sayısal_Sütunların_kolonları_Buyuk_Harf = []

        for i in sayısal_Sütunların_kolonları:
            i.capitalize()
            sayısal_Sütunların_kolonları_Buyuk_Harf.append(i)

        st.markdown(":red[Sütun Seçimi] : ")
        x_Kolon_Secim = st.selectbox("" , options=sayısal_Sütunların_kolonları_Buyuk_Harf , index = None , placeholder="X Sütununu Seçiniz")
        y_Kolon_Secim = st.selectbox("" , options=sayısal_Sütunların_kolonları_Buyuk_Harf , index = None , placeholder="Y Sütununu Seçiniz")

        if    x_Kolon_Secim is not None   and    y_Kolon_Secim is not None:
            if x_Kolon_Secim == y_Kolon_Secim:
                st.warning("Aynı Sütunları Seçtiniz")
                "---"
            else:
                st.success("Sütun Seçimi Başarılı")
                "---"

            grafikCizim(x_Kolon_Secim,y_Kolon_Secim)

    else:
        st.warning("⚠️Dosya Yüklenmedi ! Lütfen Veri Önizleme Kısmından Dosyanızı Yükleyiniz.")


except Exception as e:

    st.write(f"HATA : {e}")
    print(e)

# index = None,  >>>   Başlangıçta seçim olmasın
# key="...": session_state'te kontrol etmek için benzersiz bir anahtar.