import {
    ApiError,
    apiRequest,
    clearMessage,
    getCsrfToken,
    setBusy,
    showMessage,
} from "/static/js/api.js";


const form = document.querySelector("#login-form");
const submitButton = document.querySelector("#login-submit");
const message = document.querySelector("#login-message");


async function initialize() {
    if (new URLSearchParams(window.location.search).get("registered") === "1") {
        showMessage(message, "Регистрация завершена. Теперь войдите.", "success");
    }
    try {
        await getCsrfToken();
    } catch (_error) {
        showMessage(message, "Не удалось подготовить форму. Обновите страницу.");
    }
}


form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(message);
    setBusy(submitButton, true, "Вход...");

    try {
        await apiRequest("/api/auth/login", {
            method: "POST",
            json: {
                username: form.elements.username.value,
                password: form.elements.password.value,
            },
        });
        form.elements.password.value = "";
        window.location.replace("/notes");
    } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
            showMessage(message, "Неверный логин или пароль.");
        } else if (error instanceof ApiError && error.status === 403) {
            showMessage(message, "Учётная запись отключена или запрос отклонён.");
        } else if (error instanceof ApiError && error.status === 422) {
            showMessage(message, "Проверьте имя пользователя и пароль.");
        } else {
            showMessage(message, "Не удалось выполнить вход. Попробуйте ещё раз.");
        }
    } finally {
        setBusy(submitButton, false);
    }
});


initialize();
