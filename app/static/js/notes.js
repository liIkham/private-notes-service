import {
    ApiError,
    apiRequest,
    bindLogout,
    clearMessage,
    formatDate,
    getCsrfToken,
    isAuthenticationError,
    setBusy,
    showMessage,
} from "/static/js/api.js";


const username = document.querySelector("#current-username");
const adminLink = document.querySelector("#admin-link");
const logoutButton = document.querySelector("#logout-button");
const newNoteButton = document.querySelector("#new-note-button");
const editor = document.querySelector("#note-editor");
const formTitle = document.querySelector("#note-form-title");
const form = document.querySelector("#note-form");
const titleInput = document.querySelector("#note-title");
const contentInput = document.querySelector("#note-content");
const submitButton = document.querySelector("#note-submit");
const cancelButton = document.querySelector("#note-cancel");
const message = document.querySelector("#notes-message");
const loading = document.querySelector("#notes-loading");
const list = document.querySelector("#notes-list");
const empty = document.querySelector("#notes-empty");

let editingId = null;


function redirectIfUnauthenticated(error) {
    if (isAuthenticationError(error)) {
        window.location.replace("/login");
        return true;
    }
    return false;
}


function closeEditor() {
    editingId = null;
    form.reset();
    formTitle.textContent = "Новая заметка";
    editor.hidden = true;
}


function openCreateEditor() {
    editingId = null;
    form.reset();
    formTitle.textContent = "Новая заметка";
    editor.hidden = false;
    titleInput.focus();
}


function openEditEditor(note) {
    editingId = note.id;
    titleInput.value = note.title;
    contentInput.value = note.content;
    formTitle.textContent = "Изменить заметку";
    editor.hidden = false;
    titleInput.focus();
}


function makeButton(label, className, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", handler);
    return button;
}


function renderNotes(notes) {
    list.replaceChildren();
    empty.hidden = notes.length !== 0;

    for (const note of notes) {
        const card = document.createElement("article");
        card.className = "note-card";

        const heading = document.createElement("h3");
        heading.textContent = note.title;

        const content = document.createElement("p");
        content.className = "note-card__content";
        content.textContent = note.content;

        const meta = document.createElement("p");
        meta.className = "note-card__meta";
        meta.textContent = `Обновлена: ${formatDate(note.updated_at)}`;

        const actions = document.createElement("div");
        actions.className = "note-card__actions";
        actions.append(
            makeButton("Изменить", "button button--secondary", () => openEditEditor(note)),
            makeButton("Удалить", "button button--danger", () => deleteNote(note.id)),
        );

        card.append(heading, content, meta, actions);
        list.append(card);
    }
}


async function loadNotes() {
    loading.hidden = false;
    try {
        const notes = await apiRequest("/api/notes");
        renderNotes(notes);
    } catch (error) {
        if (!redirectIfUnauthenticated(error)) {
            showMessage(message, "Не удалось загрузить заметки. Попробуйте ещё раз.");
        }
    } finally {
        loading.hidden = true;
    }
}


async function deleteNote(noteId) {
    if (!window.confirm("Удалить эту заметку? Это действие нельзя отменить.")) {
        return;
    }
    clearMessage(message);
    try {
        await apiRequest(`/api/notes/${noteId}`, {method: "DELETE"});
        if (editingId === noteId) {
            closeEditor();
        }
        await loadNotes();
        showMessage(message, "Заметка удалена.", "success");
    } catch (error) {
        if (redirectIfUnauthenticated(error)) {
            return;
        }
        if (error instanceof ApiError && error.status === 404) {
            showMessage(message, "Заметка больше не существует.");
            await loadNotes();
        } else {
            showMessage(message, "Не удалось удалить заметку. Попробуйте ещё раз.");
        }
    }
}


form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearMessage(message);
    setBusy(submitButton, true);

    const payload = {title: titleInput.value, content: contentInput.value};
    const path = editingId === null ? "/api/notes" : `/api/notes/${editingId}`;
    const method = editingId === null ? "POST" : "PATCH";

    try {
        await apiRequest(path, {method, json: payload});
        closeEditor();
        await loadNotes();
        showMessage(message, "Заметка сохранена.", "success");
    } catch (error) {
        if (redirectIfUnauthenticated(error)) {
            return;
        }
        if (error instanceof ApiError && error.status === 404) {
            showMessage(message, "Заметка больше не существует.");
            closeEditor();
            await loadNotes();
        } else if (error instanceof ApiError && error.status === 422) {
            showMessage(message, "Проверьте заголовок и текст заметки.");
        } else {
            showMessage(message, "Не удалось сохранить заметку. Попробуйте ещё раз.");
        }
    } finally {
        setBusy(submitButton, false);
    }
});


newNoteButton.addEventListener("click", openCreateEditor);
cancelButton.addEventListener("click", closeEditor);
bindLogout(logoutButton, message);


async function initialize() {
    try {
        const [currentUser] = await Promise.all([
            apiRequest("/api/auth/me"),
            getCsrfToken(),
        ]);
        username.textContent = currentUser.username;
        adminLink.hidden = currentUser.role !== "admin";
        await loadNotes();
    } catch (error) {
        if (!redirectIfUnauthenticated(error)) {
            showMessage(message, "Не удалось загрузить страницу. Попробуйте ещё раз.");
            loading.hidden = true;
        }
    }
}


initialize();
