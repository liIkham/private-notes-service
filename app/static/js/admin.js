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
const logoutButton = document.querySelector("#logout-button");
const message = document.querySelector("#admin-message");
const usersLoading = document.querySelector("#users-loading");
const usersTable = document.querySelector("#users-table");
const usersBody = document.querySelector("#users-body");
const notesLoading = document.querySelector("#admin-notes-loading");
const notesEmpty = document.querySelector("#admin-notes-empty");
const notesTable = document.querySelector("#admin-notes-table");
const notesBody = document.querySelector("#admin-notes-body");

let currentUserId = null;


function textCell(value, className = "") {
    const cell = document.createElement("td");
    cell.textContent = String(value);
    if (className) {
        cell.className = className;
    }
    return cell;
}


function handleAccessError(error) {
    if (isAuthenticationError(error)) {
        window.location.replace("/login");
        return true;
    }
    if (error instanceof ApiError && error.status === 403) {
        window.location.replace("/notes");
        return true;
    }
    return false;
}


async function saveUser(user, roleSelect, activeCheckbox, button) {
    const removesAccess = (
        (user.role === "admin" && roleSelect.value === "user")
        || (user.is_active && !activeCheckbox.checked)
    );
    if (removesAccess && !window.confirm("Применить изменение, ограничивающее доступ пользователя?")) {
        return;
    }
    clearMessage(message);
    setBusy(button, true);
    try {
        await apiRequest(`/api/admin/users/${user.id}`, {
            method: "PATCH",
            json: {
                role: roleSelect.value,
                is_active: activeCheckbox.checked,
            },
        });
        await loadUsers();
        showMessage(message, "Пользователь обновлён.", "success");
    } catch (error) {
        if (handleAccessError(error)) {
            return;
        }
        if (error instanceof ApiError && error.status === 409) {
            showMessage(message, "Нельзя понизить или отключить собственную учётную запись.");
        } else if (error instanceof ApiError && error.status === 404) {
            showMessage(message, "Пользователь больше не существует.");
            await loadUsers();
        } else if (error instanceof ApiError && error.status === 422) {
            showMessage(message, "Выбраны некорректные параметры пользователя.");
        } else {
            showMessage(message, "Не удалось обновить пользователя. Попробуйте ещё раз.");
        }
    } finally {
        setBusy(button, false);
    }
}


function renderUsers(users) {
    usersBody.replaceChildren();
    for (const user of users) {
        const row = document.createElement("tr");
        const roleCell = document.createElement("td");
        const roleSelect = document.createElement("select");
        roleSelect.setAttribute("aria-label", `Роль пользователя ${user.username}`);
        for (const role of ["user", "admin"]) {
            const option = document.createElement("option");
            option.value = role;
            option.textContent = role;
            option.selected = user.role === role;
            roleSelect.append(option);
        }
        roleCell.append(roleSelect);

        const activeCell = document.createElement("td");
        const activeCheckbox = document.createElement("input");
        activeCheckbox.type = "checkbox";
        activeCheckbox.checked = user.is_active;
        activeCheckbox.setAttribute("aria-label", `Активность пользователя ${user.username}`);
        activeCell.append(activeCheckbox);

        const actionCell = document.createElement("td");
        const saveButton = document.createElement("button");
        saveButton.type = "button";
        saveButton.className = "button button--small button--primary";
        saveButton.textContent = "Сохранить";

        const isSelf = user.id === currentUserId;
        if (isSelf) {
            roleSelect.disabled = true;
            activeCheckbox.disabled = true;
            saveButton.disabled = true;
            saveButton.title = "Собственную роль и активность менять нельзя";
        } else {
            saveButton.addEventListener("click", () => {
                saveUser(user, roleSelect, activeCheckbox, saveButton);
            });
        }
        actionCell.append(saveButton);

        row.append(
            textCell(user.id),
            textCell(user.username),
            roleCell,
            activeCell,
            textCell(formatDate(user.created_at)),
            actionCell,
        );
        usersBody.append(row);
    }
    usersTable.hidden = false;
}


async function loadUsers() {
    usersLoading.hidden = false;
    try {
        renderUsers(await apiRequest("/api/admin/users"));
    } catch (error) {
        if (!handleAccessError(error)) {
            showMessage(message, "Не удалось загрузить пользователей.");
        }
    } finally {
        usersLoading.hidden = true;
    }
}


function renderNotes(notes) {
    notesBody.replaceChildren();
    notesEmpty.hidden = notes.length !== 0;
    notesTable.hidden = notes.length === 0;

    for (const note of notes) {
        const row = document.createElement("tr");
        row.append(
            textCell(note.id),
            textCell(note.owner_id),
            textCell(note.title),
            textCell(note.content, "table-note-content"),
            textCell(formatDate(note.created_at)),
            textCell(formatDate(note.updated_at)),
        );
        notesBody.append(row);
    }
}


async function loadNotes() {
    notesLoading.hidden = false;
    try {
        renderNotes(await apiRequest("/api/admin/notes"));
    } catch (error) {
        if (!handleAccessError(error)) {
            showMessage(message, "Не удалось загрузить заметки.");
        }
    } finally {
        notesLoading.hidden = true;
    }
}


bindLogout(logoutButton, message);


async function initialize() {
    try {
        const [currentUser] = await Promise.all([
            apiRequest("/api/auth/me"),
            getCsrfToken(),
        ]);
        if (currentUser.role !== "admin") {
            window.location.replace("/notes");
            return;
        }
        currentUserId = currentUser.id;
        username.textContent = currentUser.username;
        await Promise.all([loadUsers(), loadNotes()]);
    } catch (error) {
        if (!handleAccessError(error)) {
            showMessage(message, "Не удалось загрузить админ-панель.");
            usersLoading.hidden = true;
            notesLoading.hidden = true;
        }
    }
}


initialize();
