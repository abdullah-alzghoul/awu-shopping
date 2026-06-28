
window.addEventListener("scroll", () => {
    if (window.scrollY > 100) {
        headerElement.classList.add("scroll-down");
    } else {
        headerElement.classList.remove("scroll-down");
    }
});
document.addEventListener('DOMContentLoaded', function () {

    const container   = document.getElementById('container');
    const registerBtn = document.getElementById('register');
    const loginBtn    = document.getElementById('login');

    if (container && registerBtn && loginBtn) {
        registerBtn.addEventListener('click', () => {
            container.classList.add('active');
        });
        loginBtn.addEventListener('click', () => {
            container.classList.remove('active');
        });
    }
    const sendBtn = document.getElementById('sendCodeBtn');
    function getCsrfToken() {
        const field = document.querySelector('input[name="csrf_token"]');
        return field ? field.value : '';
    }
    if (sendBtn) {
        sendBtn.addEventListener('click', function () {
            const name  = document.getElementById('name').value.trim();
            const email = document.getElementById('email').value.trim();
            const msgEl = document.getElementById('code_msg');

            if (!email) {
                msgEl.style.color = 'red';
                msgEl.textContent = 'Please enter your email address first.';
                return;
            }

            sendBtn.disabled = true;
            sendBtn.textContent = 'Sending...';

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '../api/send_code.php', true);
            xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

            xhr.onload = function () {
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send Code';
                if (xhr.status === 200) {
                    try {
                        const res = JSON.parse(xhr.responseText);
                        msgEl.style.color = res.success ? 'green' : 'red';
                        msgEl.textContent = res.message;
                    } catch (e) {
                        msgEl.style.color = 'red';
                        msgEl.textContent = 'An unexpected error occurred.';
                    }
                } else {
                    msgEl.style.color = 'red';
                    msgEl.textContent = 'Unable to connect to the server';
                }
            };

            const data = 'name='       + encodeURIComponent(name) +
                         '&email='     + encodeURIComponent(email) +
                         '&csrf_token=' + encodeURIComponent(getCsrfToken());
            xhr.send(data);
        });
    }

    let protectedButtons = document.querySelectorAll('.requires-login');
    protectedButtons.forEach(function (btn) {
        if (!btn || !btn.addEventListener) return;
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            window.location.href = './pages/register.php?panel=signin';
        });
    });

});