document.addEventListener("DOMContentLoaded", function() {
    const fileFilterInput = document.getElementById("file-filter");
    const fileListTableBody = document.getElementById("file-list-table-body");

    let originalFilePaths = [];
    let allTargetDirs = [];

    try {
        const fileDataElement = document.getElementById("file-data");
        if (fileDataElement) {
            originalFilePaths = JSON.parse(fileDataElement.textContent || "[]");
        }
        const dirDataElement = document.getElementById("dir-data");
        if (dirDataElement) {
            allTargetDirs = JSON.parse(dirDataElement.textContent || "[]");
        }
    } catch (e) {
        console.error("Error parsing JSON data:", e);
        originalFilePaths = [];
        allTargetDirs = [];
    }

    let maxFilesToShow = 5;
    const maxFilesInput = document.getElementById("max-files-input");
    if (maxFilesInput) {
        maxFilesToShow = parseInt(maxFilesInput.value, 10);
        maxFilesInput.addEventListener("change", function(event) {
            const newValue = parseInt(event.target.value, 10);
            if (newValue >= 1) {
                maxFilesToShow = newValue;
                const currentFileFilter = fileFilterInput.value.toLowerCase();
                const currentDirFilter = dirFilterInput.value.toLowerCase();
                renderFilesTable(originalFilePaths.filter(fp => String(fp || "").toLowerCase().includes(currentFileFilter)));
                renderDirsTable(allTargetDirs.filter(dirP => String(dirP || "").toLowerCase().includes(currentDirFilter)));
            } else {
                event.target.value = maxFilesToShow;
            }
        });
    }

    let currentlySelectedFilePath = null;
    let currentlyChosenDirectoryPath = null;

    const selectedFileNameTitleElement = document.getElementById("selected-file-name-title");
    const dirFilterInput = document.getElementById("dir-filter-input");
    const dirListTableBody = document.getElementById("dir-list-table-body");
    const confirmMoveButton = document.getElementById("confirm-move-button");
    const currentMoveSelectionInfoElement = document.getElementById("current-move-selection-info");

    function getParentPath(filePathString) {
        if (!filePathString || typeof filePathString !== "string") return ".";
        const lastSlash = filePathString.lastIndexOf("/");
        if (lastSlash === -1) return ".";
        if (lastSlash === 0) return "/";
        return filePathString.substring(0, lastSlash);
    }

    function updateMoveSelectionInfo() {
        if (!currentMoveSelectionInfoElement) return;

        if (selectedFileNameTitleElement) {
            if (currentlySelectedFilePath) {
                selectedFileNameTitleElement.textContent = `Select a destination for ${currentlySelectedFilePath}`;
            } else {
                selectedFileNameTitleElement.textContent = "Select a destination for the file";
            }
        }

        if ((!currentlySelectedFilePath) && currentlyChosenDirectoryPath) {
            currentMoveSelectionInfoElement.innerHTML = `Selected destination: <strong>${currentlyChosenDirectoryPath}</strong>. Please select a file to move.`;
            confirmMoveButton.disabled = true;
        } else if (currentlySelectedFilePath && (!currentlyChosenDirectoryPath)) {
            currentMoveSelectionInfoElement.innerHTML = `Moving <strong>${currentlySelectedFilePath}</strong> to (select destination).`;
            confirmMoveButton.disabled = true;
        } else if (currentlySelectedFilePath && currentlyChosenDirectoryPath) {
            currentMoveSelectionInfoElement.innerHTML = `Move <strong>${currentlySelectedFilePath}</strong> to <strong>${currentlyChosenDirectoryPath}</strong>`;
            confirmMoveButton.disabled = false;
        } else {
            currentMoveSelectionInfoElement.textContent = "Please select a file and a destination.";
            confirmMoveButton.disabled = true;
        }
    }

    function renderList(tbodyElement, items, config) {
        tbodyElement.innerHTML = "";

        items.slice(0, maxFilesToShow).forEach(item => {
            const row = tbodyElement.insertRow();
            const itemPathString = config.itemType === "dir" ? String(item || ".") : String(item);

            const buttonCell = row.insertCell();
            buttonCell.classList.add("page-table-button-cell");
            const pathCell = row.insertCell();
            pathCell.classList.add("page-table-path-cell");

            const button = document.createElement("button");
            button.type = "button";
            button.className = `btn btn-sm m-1 ${config.buttonClassBase} ${config.buttonClassOutline}`;
            button.dataset[config.itemType === "file" ? "filePath" : "dirPath"] = itemPathString;

            if (itemPathString === config.selectedItem) {
                row.classList.add("page-item-selected");
                button.textContent = config.buttonTextSelected;
                button.classList.remove(config.buttonClassOutline);
                button.classList.add(config.buttonClassActive);
            } else {
                button.textContent = config.buttonTextDefault;
            }

            if (config.disableCondition(itemPathString, currentlySelectedFilePath, currentlyChosenDirectoryPath, getParentPath)) {
                button.disabled = true;
            }

            button.addEventListener("click", config.eventHandler);

            const span = document.createElement("span");
            span.className = "page-file-select-text";
            span.textContent = itemPathString;

            buttonCell.appendChild(button);
            pathCell.appendChild(span);
        });

        const moreInfoElement = document.getElementById(config.moreInfoId);
        if (moreInfoElement) {
            if (items.length > maxFilesToShow) {
                moreInfoElement.textContent = `${items.length - maxFilesToShow} more available (filter to browse)...`;
                moreInfoElement.style.display = "block";
            } else {
                moreInfoElement.textContent = "";
                moreInfoElement.style.display = "none";
            }
        }
    }

    function renderDirsTable(dirsToShow) {
        const dirsConfig = {
            itemType: "dir",
            selectedItem: currentlyChosenDirectoryPath,
            buttonClassBase: "choose-dir-btn",
            buttonClassOutline: "btn-outline-secondary",
            buttonClassActive: "btn-secondary",
            buttonTextSelected: "Chosen",
            buttonTextDefault: "Choose",
            eventHandler: handleDirChooseClick,
            moreInfoId: "dir-list-more-info",
            disableCondition: (itemPath, selectedFile, _chosenDir, getParent) => selectedFile && (getParent(selectedFile) === itemPath)
        };
        renderList(dirListTableBody, dirsToShow, dirsConfig);
    }

    function handleDirChooseClick(event) {
        currentlyChosenDirectoryPath = event.target.dataset.dirPath;
        const filterText = dirFilterInput.value.toLowerCase();
        const filteredDirs = allTargetDirs.filter(dirP => String(dirP || "").toLowerCase().includes(filterText));
        renderDirsTable(filteredDirs);

        const fileFilterText = fileFilterInput.value.toLowerCase();
        const filteredFilePaths = originalFilePaths.filter(fp => String(fp || "").toLowerCase().includes(fileFilterText));
        renderFilesTable(filteredFilePaths);

        updateMoveSelectionInfo();
    }

    function handleFileSelectButtonClick(event) {
        const newlySelectedFilePath = event.target.dataset.filePath;

        if (currentlyChosenDirectoryPath) {
            const parentOfNewFile = getParentPath(newlySelectedFilePath);
            if (parentOfNewFile === currentlyChosenDirectoryPath) {
                currentlyChosenDirectoryPath = null;
            }
        }

        currentlySelectedFilePath = newlySelectedFilePath;

        const fileFilterText = fileFilterInput.value.toLowerCase();
        const filteredFilePaths = originalFilePaths.filter(fp => String(fp || "").toLowerCase().includes(fileFilterText));
        renderFilesTable(filteredFilePaths);

        const dirFilterText = dirFilterInput.value.toLowerCase();
        const filteredDirs = allTargetDirs.filter(dirP => String(dirP || "").toLowerCase().includes(dirFilterText));
        renderDirsTable(filteredDirs);

        updateMoveSelectionInfo();
    }

    function renderFilesTable(pathsToShow) {
        const filesConfig = {
            itemType: "file",
            selectedItem: currentlySelectedFilePath,
            buttonClassBase: "select-file-btn",
            buttonClassOutline: "btn-outline-primary",
            buttonClassActive: "btn-primary",
            buttonTextSelected: "Selected",
            buttonTextDefault: "Select",
            eventHandler: handleFileSelectButtonClick,
            moreInfoId: "file-list-more-info",
            disableCondition: (itemPath, _selectedFile, chosenDir, getParent) => chosenDir && (getParent(itemPath) === chosenDir)
        };
        renderList(fileListTableBody, pathsToShow, filesConfig);
    }

    if (dirFilterInput) {
        dirFilterInput.addEventListener("input", function() {
            const filterText = dirFilterInput.value.toLowerCase();
            const filteredDirs = allTargetDirs.filter(dirPath => {
                return String(dirPath || "").toLowerCase().includes(filterText);
            });
            renderDirsTable(filteredDirs);
        });
    }

    fileFilterInput.addEventListener("input", function() {
        const filterText = fileFilterInput.value.toLowerCase();
        const filteredPaths = originalFilePaths.filter(filePath => {
            return String(filePath || "").toLowerCase().includes(filterText);
        });
        renderFilesTable(filteredPaths);
    });

    renderFilesTable(originalFilePaths);
    renderDirsTable(allTargetDirs);

    if (confirmMoveButton) {
        confirmMoveButton.addEventListener("click", function() {
            if (currentlySelectedFilePath && currentlyChosenDirectoryPath) {
                const formData = new FormData();
                const mainScriptElement = document.getElementById("main-script-data");
                const csrfToken = mainScriptElement.dataset.csrfToken;
                formData.append("csrf_token", csrfToken);
                formData.append("source_file", currentlySelectedFilePath);
                formData.append("target_directory", currentlyChosenDirectoryPath);
                fetch(window.location.pathname, {
                        method: "POST",
                        body: formData,
                    })
                    .then(response => {
                        if (response.ok) {
                            window.location.reload();
                        } else {
                            alert("An error occurred while moving the file.");
                        }
                    })
                    .catch(() => {
                        alert("A network error occurred.");
                    });
            } else {
                alert("Please select both a file to move and a destination directory.");
            }
        });
    }

    updateMoveSelectionInfo();
});
