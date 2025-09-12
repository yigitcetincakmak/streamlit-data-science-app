import streamlit as st

import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash

import time



# Oturum durumu ve kullanıcının bilgisi için session_state

if "login" not in st.session_state:
    st.session_state["login"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None



st.title("📈 Data Analysis Project")
# st.write("---")




conn = psycopg2.connect(
    host="localhost",
    dbname="streamlitdb",
    user="postgres",
    password="9831431797",
    port="5432"
)
cur = conn.cursor()




# kayıt ol / giriş yap seçenekleri
tab1, tab2 = st.tabs(["Kayıt Ol", "Giriş Yap"])


# Kayıt Olma
with tab1:
    st.header("🔐 - Kayıt Ol")
    st.subheader("Yeni Kullanıcı Kaydı :")

    new_email = st.text_input("Email", key="signup_email")
    new_password = st.text_input("Şifre", type="password", key="signup_password")

    if st.button("Kayıt Ol", key="signup_btn"):
        if new_email == "" or new_password == "":
            st.warning("Email veya şifre boş bırakılamaz!")

        elif len(new_password) < 6:
            st.warning("Şifre en az 6 karakter olmalıdır!")

        elif not any(char.isupper() for char in new_password):
            st.warning("Şifre en az 1 büyük harf içermelidir!")

        elif not any(char.islower() for char in new_password):
            st.warning("Şifre en az 1 küçük harf içermelidir!")

        elif not any(char.isdigit() for char in new_password):
            st.warning("Şifre en az 1 rakam içermelidir!")

        elif not any(char in "!@#$%^&*()_+-=?" for char in new_password):
            st.warning("Şifre en az 1 özel karakter içermelidir (!@#$%^&*()_+-=?)")

        else:
            try:
                hashed_pw = generate_password_hash(new_password)
                cur.execute(
                    "INSERT INTO users (email, password) VALUES (%s, %s);",
                    (new_email, hashed_pw)
                )
                conn.commit()
                st.success(f"{new_email} başarıyla kayıt oldu! Giriş yapabilirsiniz.")
                time.sleep(1.50)

                # Oturumu aç
                st.session_state["login"] = True
                st.session_state["user_email"] = new_email
                st.rerun()

            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                st.error("Bu email zaten kayıtlı!")




                                    # ------------------ Giriş Yap Sekmesi ------------------
with tab2:
    st.header("🔓 - Giriş Yap")
    st.subheader("Mevcut Kullanıcı Girişi :")

    login_email = st.text_input("Email", key="login_email")
    login_password = st.text_input("Şifre", type="password", key="login_password")


    if st.button("Giriş Yap", key="login_btn"):
        cur.execute("SELECT password FROM users WHERE email = %s", (login_email,))
        result = cur.fetchone()

        if result and check_password_hash(result[0], login_password):
            st.success("Giriş başarılı! Lütfen sol menüden Veri Önizleme sayfasına geçin.")
            time.sleep(3)
            st.session_state["login"] = True
            st.session_state["user_email"] = login_email
            st.rerun()
        else:
            st.error("Email veya şifre hatalı!")
