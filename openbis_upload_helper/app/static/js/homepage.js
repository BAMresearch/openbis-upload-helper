                                        const dropArea = document.getElementById('drop-area');
                                        const fileInput = document.getElementById('fileElem');
                                        const fileList = document.getElementById('file-list');

                                        dropArea.addEventListener('click', () => {
                                            fileInput.click();
                                        });

                                        fileInput.addEventListener('change', () => {
                                            handleFiles(fileInput.files);
                                        });

                                        dropArea.addEventListener('dragover', (e) => {
                                            e.preventDefault();
                                            dropArea.classList.add('highlight');
                                        });

                                        dropArea.addEventListener('dragleave', () => {
                                            dropArea.classList.remove('highlight');
                                        });

                                        // add files to input form
                                        dropArea.addEventListener('drop', (e) => {
                                            e.preventDefault();
                                            dropArea.classList.remove('highlight');
                                            fileInput.files = e.dataTransfer.files;
                                            handleFiles(e.dataTransfer.files);
                                        });
                                        //handle files and display them + checkboxes
                                        async function handleFiles(files) {
                                          fileList.innerHTML = '';
                                          for (let i = 0; i < files.length; i++) {
                                            const file = files[i];
                                            const li = document.createElement('li');
                                            // checkbox
                                            const checkbox = document.createElement('input');
                                            checkbox.type = 'checkbox';
                                            checkbox.value = file.name;
                                            checkbox.checked = true; // default checked
                                            checkbox.style.marginRight = '10px';
                                            if (file.name.endsWith('.zip')) {
                                              checkbox.disabled = true;
                                              checkbox.checked = false;
                                            }
                                            if (file.name.endsWith('.tar')) {
                                              checkbox.disabled = true;
                                              checkbox.checked = false;
                                            }
                                            if (checkbox.disabled==true) {
                                              checkbox.hidden = true; // hide checkbox for compressed files
                                            }
                                            li.appendChild(checkbox);


                                            const label = document.createElement('label');
                                            label.textContent = file.name;
                                            li.appendChild(label);


                                            if (file.name.endsWith('.zip')) {
                                              const arrayBuffer = await file.arrayBuffer();
                                              const zip = await JSZip.loadAsync(arrayBuffer);

                                              const ul = document.createElement('ul');
                                              for (const filename in zip.files) {
                                                const zipEntry = zip.files[filename];
                                                if (!zipEntry.dir) {
                                                    const fileLi = document.createElement('li');

                                                    const innerCheckbox = document.createElement('input');
                                                    innerCheckbox.type = 'checkbox';
                                                    innerCheckbox.value = filename;
                                                    innerCheckbox.style.marginRight = '10px';
                                                    innerCheckbox.checked = true; // default checked

                                                    const innerLabel = document.createElement('label');
                                                    innerLabel.textContent = filename;

                                                    fileLi.appendChild(innerCheckbox);
                                                    fileLi.appendChild(innerLabel);
                                                    ul.appendChild(fileLi);
                                                }
                                              }
                                              li.appendChild(ul);
                                            }
                                            fileList.appendChild(li);
                                          }
                                        }
                                        function getSelectedFiles() {
                                          const selected = [];
                                          document.querySelectorAll('#file-list input[type=checkbox]:checked').forEach(cb => {
                                            selected.push(cb.value);
                                          });
                                          console.log("Selected files:", selected);
                                          return selected;
                                        }

                                        document.getElementById('upload-form').addEventListener('submit', function() {
                                          const selected = getSelectedFiles();
                                          console.log("Selected files:", selected); // Debug
                                          document.getElementById('selected-files-input').value = selected.join(',');
                                        });