from cProfile import label

import matplotlib.pyplot as plt
import  streamlit as st

from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsRegressor

from sklearn.metrics import mean_squared_error ,r2_score


st.title("🌐 Veri Modelleme")


# update : güncellemek
# interpreter : yorumlayıcı
# spinner : zamanlayıcı
# number_input

# galiba ortak işlemler için kurdum
def veriIslem(df,selectbox_key = ""):

    Sütunlar = df.columns

    target = st.selectbox("",options=Sütunlar,index = None,key=f"target_selectbox_{selectbox_key}",placeholder="Hedef Sütunu Seçiniz",)

    if target is None:

        st.warning("Öncelikli Olarak Hedef  Sütununu Seçiniz , Hedef  Sütun  Dışında  Kalan  Sütunlar  Veri  Olarak  Alınacaktır.")
    else:

        target_df = df[target]
        target_ön = target_df.head(3)

        data = df.drop(columns=[target])
        data_ön = data.head(3)
        st.success("Hedef  Ve  Veri  Sütunları  Başarıyla  Ayrılarak  Oluşturuldu. ")
        st.write("Seçilen Hedef Sütun İlk  3  Satır  Gösterimi :",target_ön)
        st.write("Seçilen Veri Sütunları  İlk  3  Satır  Gösterimi :",data_ön)

        test_size = st.number_input("Eğitim İçin Alınması Gereken Veri Oranını Giriniz .", min_value=0.01, max_value=1.0, value=0.2, step=0.01)
        "---"
        if test_size is not None:
            if test_size < 0  or  test_size > 1 :
                st.warning("Lütfen 0-1 Aralğında Bir Değer Giriniz")
                return None  # veya işlem yapma
            else:
                X_train,X_test,y_train,y_test = train_test_split(data,target_df,test_size=test_size,random_state=42)
                return X_train, X_test, y_train, y_test





def KN_eighborsClassifier(bolme,key = "classifier"):

    # result = veriIslem("classifier")

    if bolme is None:
        return

    X_train, X_test, y_train, y_test = bolme #result

    # Ölçeklendirme
    scaler_izin = st.toggle("Veriyi Ölçeklendir (Scaler)",key=f"toggle_{key}")

    if scaler_izin:
        scaler = StandardScaler()

        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

    else:
        pass # Eğer ölçeklendirme yapılmayacaksa, veriyi olduğu gibi bırak

    n_neighbors = st.number_input("n_neighbors - Komşu Sayısı Parametre Değerini Giriniz", min_value=1, step=1, value=3,key=f"number_input_{key}") # tam sayı int dönmesi için ya başına int yazıp paranteze alıcaktık yada buradaki gibi bu 3 parametreyi vericez.
    if n_neighbors is not None:
        knn = KNeighborsClassifier(n_neighbors = n_neighbors)
        knn.fit(X_train,y_train)

        "---"
        st.markdown(":red[Sonuçların Değerlendirilmesi]:")
        y_pred = knn.predict(X_test)
        accuracy = accuracy_score(y_test,y_pred)
        st.write("Doğruluk Oranı: ",accuracy)

        confusion_Matrix = confusion_matrix(y_test,y_pred)
        st.write("Confusion Matrix :")
        st.write(confusion_Matrix)

        "---"
        n_Neighbors_Parametre_Degerleri = []
        dogruluk_Degerleri = []
        for k in range(1,21):
            knn = KNeighborsClassifier(n_neighbors = k)
            knn.fit(X_train,y_train)
            y_pred = knn.predict(X_test)
            accuracy = accuracy_score(y_test,y_pred)

            n_Neighbors_Parametre_Degerleri.append(k)
            dogruluk_Degerleri.append(accuracy)

        plt.figure()
        plt.plot(n_Neighbors_Parametre_Degerleri,dogruluk_Degerleri,marker = "o",linestyle ="-")
        plt.xlabel("n_neighbors Parametre Değerleri")
        plt.ylabel("Doğruluk Oranları")
        plt.xticks(n_Neighbors_Parametre_Degerleri)
        plt.grid(True)
        st.pyplot(plt)

        max_Dogruluk = max(dogruluk_Degerleri)
        max_index = dogruluk_Degerleri.index(max_Dogruluk)  # bu sadece index
        optimum_k = n_Neighbors_Parametre_Degerleri[max_index]  # buradan gerçek k değeri

        st.write("Tavsiye Edilen n_neighbors Parametre Değeri :")
        st.write(f"Oluşturulan Grafiğe Göre  :blue[{max_Dogruluk:.4f}]  Doğruluk Oranı ile  En İyi n_neighbors Parametre Değeri :blue[{optimum_k}] Değeridir Modelinizi Bu Değer ile Deneyebilirsiniz.")
        "---"

def KN_Regressor(bolme,key ="regressor"):

    #result = veriIslem("regressor")

    if bolme is None:
        return

    X_train, X_test, y_train, y_test = bolme   #result

    scaler_izin = st.toggle("Veriyi Ölçeklendir (Scaler)",key=f"toggle_{key}")
    if scaler_izin:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

    n_neighbors = st.number_input("n_neighbors - Komşu Sayısı Parametre Değerini Giriniz", min_value=1, step=1,value=3,key=f"number_input{key}")  # tam sayı int dönmesi için ya başına int yazıp paranteze alıcaktık yada buradaki gibi bu 3 parametreyi vericez.
    weight = st.radio("weight Parametresini seçiniz :",["uniform","distance"])

    if n_neighbors and weight is not None:

        st.write("Seçilen Değer : :green[{weight}]")
        knn = KNeighborsRegressor(n_neighbors = n_neighbors , weights = weight)
        knn.fit(X_train,y_train)
        y_pred = knn.predict(X_test)

        mse = mean_squared_error(y_test,y_pred)
        r2 = r2_score(y_test,y_pred)

        st.write(f"Mean Squared Error Değeri :  :blue[{mse:.2f}]")
        st.write(f"r² Skor Değeri : :blue[{r2:.2f}]") # Alt + 0178 kare üssü 2 yapıyor # rainbow -- blue yerine olabilir
        "---"

        for i , weight in enumerate(["uniform","distance"]):
            knn = KNeighborsRegressor(n_neighbors=n_neighbors, weights=weight)
            knn.fit(X_train, y_train)
            y_pred = knn.predict(X_test)

            plt.subplot(2,1,i+1) # 2 satır 1 sütundan oluşan , ve galiba 1.çiziyorum ... gibi
            plt.scatter(X_train,y_train,color = "black",label="veri")
            plt.plot(X_test,y_pred,color = "red" , label ="tahmin")
            plt.axis("tight")
            plt.legend()
            plt.title(f"KNN Regressor weight = {weight}")

        plt.tight_layout()
        st.pyplot(plt)


# def Locistic_Regression():








def ML_Secım():

    secim = st.multiselect(" :red[ML Algoritmasını Seçiniz :]",["KNeighborsClassifier","KNRegressor"])

    if "KNeighborsClassifier" in secim:

        with st.expander("KNeighborsClassifier"):

            KN_eighborsClassifier(bolme)

    if "KNRegressor" in secim:

        with st.expander("KNRegressor"):

            KN_Regressor(bolme)


try:


    if "veri" in st.session_state:
        df = st.session_state["veri"]

        st.success("Dosyanız Başarıyla Yüklenmiştir")
        "---"

        dosya_Adi = st.session_state.get("dosya_Adi", "Bilinmeyen_Dosya")

        st.write("Yüklenen Dosya : ", dosya_Adi)

        "---"
        bolme = veriIslem(df,"shared")  # veriIslem sadece burada çağrılır


        # bence kullanıcı multi seçim yapsın seçtikleri expendar da görülsün oluşturulsun

        ML_Secım()

        #KN_eighborsClassifier(bolme)
        #KN_Regressor(bolme)

    else:
        st.warning("⚠️Dosya Yüklenmedi ! Lütfen Veri Önizleme Kısmından Dosyanızı Yükleyiniz.")

except Exception as e:
    st.write(":green[Yakalanan Hata]: ",e)


#  dökümantasyonda metrik kısmında ornek 4 de ızgara kısmını makine öğrenmesi için doğruluk oranı


# ÖNCE ML ALGORİTMASINI SEÇSİN SONRA EXPLANDERDA PARAMETRES SORSUN