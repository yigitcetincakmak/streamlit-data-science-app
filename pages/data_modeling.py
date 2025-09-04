import matplotlib.pyplot as plt
import seaborn as sns
import streamlit as st

from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsRegressor
from sklearn.linear_model  import LogisticRegression
from sklearn.metrics import mean_squared_error ,r2_score
from sklearn.tree import DecisionTreeClassifier,plot_tree


st.title("🌐 Veri Modelleme")




# ortak işlemler için kurdum
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

        try:
          knn.fit(X_train,y_train)

        except ValueError:

           st.error("⚠️ Seçtiğiniz hedef değişken sürekli sayısal değerler içeriyor. "
                "Lütfen sınıflandırma için kategorik bir sütun seçin veya regresyon algoritması kullanın.")

           st.stop()

        "---"
        st.markdown(":red[Sonuçların Değerlendirilmesi]:")
        y_pred = knn.predict(X_test)
        accuracy = accuracy_score(y_test,y_pred)
        st.write("Doğruluk Oranı: ",accuracy)

        confusion_Matrix = confusion_matrix(y_test,y_pred)

        st.write("Confusion Matrix:")
        fig, ax = plt.subplots()
        sns.heatmap(confusion_Matrix, annot=True, fmt="d", cmap="magma", ax=ax, cbar=False,linewidths=1, linecolor="black")
        ax.set_xlabel("Tahmin")
        ax.set_ylabel("Gerçek")
        st.pyplot(fig)


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

        try:

            knn.fit(X_train,y_train)

        except ValueError:

             st.error("⚠️ Seçtiğiniz hedef değişken kategorik değerler içeriyor. "
                      "Regresyon algoritmaları sürekli (sayısal) hedef değişkenler için uygundur. "
                      "Lütfen regresyon yerine sınıflandırma algoritması seçiniz.")

             st.stop()



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


def Locistic_Regression(bolme):

    if bolme is None:
        return

    X_train, X_test, y_train, y_test = bolme

    c =  st.number_input("Regularizasyon Katsayısı (C)" , min_value= 0.01,max_value=10.0,value=1.0,step=0.01)
    max_iter =  st.number_input("Maksimum İterasyon Sayısı" , min_value=50,max_value=1000,value=100,step = 10)



    log_regression = LogisticRegression(  penalty="l2",
                                          C=c,
                                          solver="lbfgs",
                                          max_iter = max_iter
    )

    try:

       log_regression.fit(X_train,y_train)

    except ValueError:
        st.error("⚠️ Seçtiğiniz hedef değişken sürekli sayısal değerler içeriyor. "
                     "Lütfen sınıflandırma için kategorik bir sütun seçin veya regresyon algoritması kullanın.")


        # st.stop()

    accuracy = log_regression.score(X_test,y_test)

    st.write(f"Logistic Regression Doğruluk Oranı: :blue[{accuracy:.4f}]")



    y_pred = log_regression.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)

    st.write("Confusion Matrix:")
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt="d", cmap="cividis", ax=ax,linewidths=1, linecolor="black")
    ax.set_xlabel("Tahmin")
    ax.set_ylabel("Gerçek")
    st.pyplot(fig)





def Decision_Tree(bolme):

    if bolme is None:
        return

    X_train, X_test, y_train, y_test = bolme

    criterion = st.selectbox("Bölme Kriteri (criterion):" , ["gini","entropy"])
    max_depth = st.number_input("Maksimum Derinlik (max_depth):",min_value=1 , max_value=20 , value = 5 , step =1)

    tree_clf = DecisionTreeClassifier(criterion=criterion,
                                      max_depth=max_depth,
                                      random_state=42

    )


    try:
       tree_clf.fit(X_train,y_train)

    except ValueError:
        st.error("⚠️ Seçtiğiniz hedef değişken sürekli sayısal değerler içeriyor. "
                     "Lütfen sınıflandırma için kategorik bir sütun seçin veya regresyon algoritması kullanın.")

        st.stop()


    y_pred = tree_clf.predict(X_test)
    accuracy = accuracy_score(y_test,y_pred)


    conf_matrix = confusion_matrix(y_test,y_pred)
    st.write("Confusion Matrix:")


    fig, ax = plt.subplots()
    sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="coolwarm", ax=ax, cbar=True,
                linewidths=1, linecolor="black")  # kutucuklara çizgi ekleme
    ax.set_xlabel("Tahmin")
    ax.set_ylabel("Gerçek")
    st.pyplot(fig)


    plt.figure(figsize=(35,18),dpi=100)

    # plot_tree(tree_clf,filled=True,feature_names=df.columns,class_names=list(target.columns)) # → burada df ve target Decision_Tree fonksiyonuna parametre olarak gelmiyor. Bu hata veriyor. Onu boyle yapabtık:
    plot_tree(tree_clf , filled=True , feature_names=X_train.columns , class_names=[str(cls) for cls in y_train.unique()],fontsize=10, rounded=True)

    st.pyplot(plt)



    feature_importances = tree_clf.feature_importances_
    feature_names = X_train.columns
    feature_importances_sorted = sorted(zip(feature_importances,feature_names),reverse=True)

    "---"
    st.write(":red[Ozellik Onem Skorları (Sıralı) :]")

    for importance , feature_name in feature_importances_sorted:
        st.write(f"{feature_name } : :blue[{importance}]")




def ML_Secım():

    if bolme is None:
        return

    X_train, X_test, y_train, y_test = bolme

    # Eğer hedef sütun kategorikse (az unique değer, int/string gibi)
    if y_train.dtype == 'object' or y_train.nunique() < 20:
            secim = st.multiselect(" :red[Sınıflandırma Algoritmasını Seçiniz :]",["KNeighborsClassifier","KNRegressor","Locistic_Regression","Decision_Tree"])

            if "KNeighborsClassifier" in secim:
                 with st.expander("KNeighborsClassifier"):
                      KN_eighborsClassifier(bolme)


            if "Decision_Tree" in secim:
                 with st.expander("Decision_Tree"):
                     Decision_Tree(bolme)


            if "Locistic_Regression" in secim:
                 with st.expander("Locistic_Regression"):
                     Locistic_Regression(bolme)



    else : # sürekli sayısal değerler için regresyon

            secim = st.multiselect("Regresyon Algoritmasını Seciniz:",["KNRegressor"])

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


        ML_Secım()


    else:

        st.warning("⚠️Dosya Yüklenmedi ! Lütfen Veri Önizleme Kısmından Dosyanızı Yükleyiniz.")

except Exception as e:

       st.write(":green[Yakalanan Hata]: ",e)

