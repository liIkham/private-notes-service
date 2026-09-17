import {
    ApiError,
    apiRequest,
    clearMessage,
    getCsrfToken,
    setBusy,
    showMessage,
} from "/static/js/api.js";


const form = document.querySelector("#register-form");
const submitButton = document.querySelector("#register-submit");
const message = document.querySelector("#register-message");


form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(message);

    const password = form.elements.password.value;
    const repeatedPassword = form.elements["password-repeat"].value;
    if (password !== repeatedPassword) {
        showMessage(message, "Пароли не совпадают.");
        return;
    }

    setBusy(submitButton, true, "Регистрация...");
    try {
        await apiRequest("/api/auth/register", {
            method: "POST",
            json: {
                username: form.elements.username.value,
                password,
            },
        });
        form.reset();
        window.location.replace("/login?registered=1");
    } catch (error) {
        if (error instanceof ApiError && error.status === 409) {
            showMessage(message, "Это имя пользователя уже занято.");
        } else if (error instanceof ApiError && error.status === 422) {
            showMessage(message, "Проверьте формат имени пользователя и длину пароля.");
        } else {
            showMessage(message, "Не удалось зарегистрироваться. Попробуйте ещё раз.");
        }
    } finally {
        setBusy(submitButton, false);
    }
});


getCsrfToken().catch(() => {
    showMessage(message, "Не удалось подготовить форму. Обновите страницу.");
});
