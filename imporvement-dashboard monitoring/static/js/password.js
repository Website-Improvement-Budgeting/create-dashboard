
function togglePassword(inputId, button) {

    // Ambil input dan ikon mata
    const input = document.getElementById(inputId);
    const icon = button.querySelector("i");

    if (!input || !icon) {
        return;
    }

    // Cek apakah password sedang disembunyikan
    const isHidden = input.type === "password";

    // Ubah tipe input
    input.type = isHidden ? "text" : "password";

    // Ganti ikon mata
    if (isHidden) {
        icon.classList.remove("bi-eye");
        icon.classList.add("bi-eye-slash");

        button.setAttribute(
            "aria-label",
            "Sembunyikan password"
        );

    } else {
        icon.classList.remove("bi-eye-slash");
        icon.classList.add("bi-eye");

        button.setAttribute(
            "aria-label",
            "Tampilkan password"
        );
    }

    button.setAttribute(
        "aria-pressed",
        String(isHidden)
    );
}