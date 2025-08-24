document.addEventListener('DOMContentLoaded', function() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.querySelector('#uploadArea input[type="file"]');
    const fileList = document.getElementById('fileList');
    
    // Handle drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        fileInput.files = e.dataTransfer.files;
        updateFileList();
    });
    
    // Handle click and file selection
    uploadArea.addEventListener('click', () => fileInput.click());
    
    fileInput.addEventListener('change', updateFileList);
    
    // Update file list display
    function updateFileList() {
        fileList.innerHTML = '';
        if (fileInput.files.length > 0) {
            Array.from(fileInput.files).forEach((file, index) => {
                const fileItem = document.createElement('div');
                fileItem.className = 'file-item';
                
                const fileInfo = document.createElement('div');
                fileInfo.className = 'file-info';
                
                const fileIcon = document.createElement('i');
                fileIcon.className = 'file-icon fas ' + getFileIcon(file.name);
                
                const fileName = document.createElement('span');
                fileName.textContent = file.name;
                
                const fileSize = document.createElement('span');
                fileSize.textContent = formatFileSize(file.size);
                
                const fileRemove = document.createElement('i');
                fileRemove.className = 'file-remove fas fa-times';
                fileRemove.addEventListener('click', (e) => {
                    e.stopPropagation();
                    removeFile(index);
                });
                
                fileInfo.appendChild(fileIcon);
                fileInfo.appendChild(fileName);
                fileItem.appendChild(fileInfo);
                fileItem.appendChild(fileSize);
                fileItem.appendChild(fileRemove);
                fileList.appendChild(fileItem);
            });
        }
    }
    
    // Remove file from list
    function removeFile(index) {
        const files = Array.from(fileInput.files);
        files.splice(index, 1);
        
        const dataTransfer = new DataTransfer();
        files.forEach(file => dataTransfer.items.add(file));
        fileInput.files = dataTransfer.files;
        
        updateFileList();
    }
    
    // Get appropriate icon for file type
    function getFileIcon(filename) {
        const extension = filename.split('.').pop().toLowerCase();
        const icons = {
            exe: 'fa-file-code',
            zip: 'fa-file-archive',
            rar: 'fa-file-archive',
            apk: 'fa-mobile-alt',
            dmg: 'fa-laptop',
            txt: 'fa-file-alt',
            pdf: 'fa-file-pdf',
            doc: 'fa-file-word',
            xls: 'fa-file-excel',
            ppt: 'fa-file-powerpoint',
            jpg: 'fa-file-image',
            png: 'fa-file-image',
            gif: 'fa-file-image',
            mp4: 'fa-file-video',
            mov: 'fa-file-video'
        };
        return icons[extension] || 'fa-file';
    }
    
    // Format file size
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    // Form submission
    const uploadForm = document.getElementById('uploadForm');
    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        // Here you would normally handle the file upload
        alert('سيتم رفع اللعبة بعد اكتمال التطوير الخلفي');
        // uploadForm.reset();
        // fileList.innerHTML = '';
    });
});

