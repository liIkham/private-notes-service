let csrfToken = null;


export class ApiError extends Error {
    constructor(status, detail) {
        super(typeof detail === "string" ? detail : "API request failed");
        this.name = "ApiError";
        this.status = status;
        this.detail = detail;
    }
}


function sameOriginPath(path) {
    if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//")) {
        throw new Error("API path must be same-origin");
    }
    const url = new URL(path, window.location.origin);
    if (url.origin !== window.location.origin) {
        throw new Error("Cross-origin API requests are not allowed");
    }
    return `${url.pathname}${url.search}`;
}


async function readResponse(response) {
    if (response.status === 204) {
        return null;
    }
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }
    const text = await response.text();
    return text || null;
}


export async function getCsrfToken(force = false) {
    if (csrfToken && !force) {
        return csrfToken;
    }
    const response = await fetch("/api/auth/csrf", {
        method: "GET",
        credentials: "same-origin",
        headers: {Accept: "application/json"},
    });
    const data = await readResponse(response);
    if (!response.ok || !data || typeof data.csrf_token !== "string") {
        throw new ApiError(response.status, data?.detail);
    }
    csrfToken = data.csrf_token;
    return csrfToken;
}


export async function apiRequest(path, options = {}) {
    const url = sameOriginPath(path);
    const method = (options.method || "GET").toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");

    const unsafe = !["GET", "HEAD", "OPTIONS"].includes(method);
    if (unsafe) {
        headers.set("X-CSRF-Token", await getCsrfToken());
    }

    let body = options.body;
    if (Object.hasOwn(options, "json")) {
        headers.set("Content-Type", "application/json");
        body = JSON.stringify(options.json);
    }

    const response = await fetch(url, {
        method,
        headers,
        body,
        credentials: "same-origin",
    });
    const data = await readResponse(response);
    if (!response.ok) {
        throw new ApiError(response.status, data?.detail);
    }
    return data;
}


export function showMessage(element, text, kind = "error") {
    element.textContent = text;
    element.className = `message message--${kind}`;
    element.hidden = false;
}


export function clearMessage(element) {
    element.textContent = "";
    element.hidden = true;
}


export function setBusy(button, busy, busyLabel = "Сохранение...") {
    if (busy) {
        button.dataset.originalLabel = button.textContent;
        button.textContent = busyLabel;
        button.disabled = true;
        return;
    }
    button.textContent = button.dataset.originalLabel || button.textContent;
    button.disabled = false;
}


export function formatDate(value) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
        return "—";
    }
    return new Intl.DateTimeFormat("ru-RU", {
        dateStyle: "medium",
        timeStyle: "short",
    }).format(date);
}


export function isAuthenticationError(error) {
    return error instanceof ApiError && (
        error.status === 401
        || (error.status === 403 && error.message === "Inactive user")
    );
}


async function requestLogout() {
    try {
        await apiRequest("/api/auth/logout", {method: "POST"});
    } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 403) {
            throw error;
        }

        csrfToken = null;
        await getCsrfToken(true);
        await apiRequest("/api/auth/logout", {method: "POST"});
    }
}


export function bindLogout(button, message) {
    button.addEventListener("click", async () => {
        if (message) {
            clearMessage(message);
        }
        setBusy(button, true, "Выход...");
        try {
            await requestLogout();
            csrfToken = null;
            window.location.replace("/login");
        } catch (_error) {
            setBusy(button, false);
            if (message) {
                showMessage(
                    message,
                    "Не удалось выйти. Сессия остаётся активной. Попробуйте ещё раз.",
                );
            }
        }
    });
}
