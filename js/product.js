
const cartIcon    = document.querySelector("#cart-icon");
const cart        = document.querySelector(".cart");
const cartClose   = document.querySelector("#cart-close");
const cartContent = document.querySelector(".cart-content");

cartIcon.addEventListener("click", () => {
    cart.classList.add("active");
    document.getElementById('cart-overlay').style.display = 'block';
});

cartClose.addEventListener("click", () => {
    closeCart();
});

function closeCart() {
    cart.classList.remove("active");
    document.getElementById('cart-overlay').style.display = 'none';
}

const addCartButtons = document.querySelectorAll(".add-cart");
addCartButtons.forEach(button => {
    button.addEventListener("click", event => {
        const productBox = event.target.closest(".product-box");
        if (!productBox) return;
        addToCart(productBox);
    });
});

const addToCart = productBox => {
    if (!productBox) return;
    const imgEl          = productBox.querySelector("img");
    const productImgsrc  = imgEl ? imgEl.src : '';
    const productPrice   = productBox.querySelector(".price").textContent;
    const productTitle   = productBox.querySelector(".product-title").textContent;
    const cartItems      = cartContent.querySelectorAll(".cart-product-title");

    for (let item of cartItems) {
        if (item.textContent === productTitle) {
            alert("This item is already in the cart.");
            return;
        }
    }

    const cartBox = document.createElement("div");
    cartBox.classList.add("cart-box");
    cartBox.innerHTML = `
        <img src="${productImgsrc}" class="cart-img">
        <div class="cart-detail">
            <h2 class="cart-product-title">${productTitle}</h2>
            <span class="cart-price">${productPrice}</span>
            <div class="cart-quantity">
                <button class="decrement">-</button>
                <span class="number">1</span>
                <button class="increment">+</button>
            </div>
        </div>
        <i class="ri-delete-bin-line cart-remove"></i>
    `;

    cartContent.appendChild(cartBox);

    cartBox.querySelector(".cart-remove").addEventListener("click", () => {
        cartBox.remove();
        updateCartCount(-1);
        updateTotalPrice();
    });

    cartBox.querySelector(".cart-quantity").addEventListener("click", event => {
        const numberElement   = cartBox.querySelector(".number");
        const decrementButton = cartBox.querySelector(".decrement");
        let quantity          = parseInt(numberElement.textContent);

        if (event.target.classList.contains("decrement") && quantity > 1) {
            quantity--;
            if (quantity === 1) decrementButton.style.color = "#999";
        } else if (event.target.classList.contains("increment")) {
            quantity++;
            decrementButton.style.color = "#333";
        }

        numberElement.textContent = quantity;
        updateTotalPrice();
    });

    updateCartCount(1);
    updateTotalPrice();
};

const updateTotalPrice = () => {
    const totalPriceElement = document.querySelector(".total-price");
    const cartBoxes         = cartContent.querySelectorAll(".cart-box");
    let total               = 0;

    cartBoxes.forEach(cartBox => {
        const price    = parseFloat(cartBox.querySelector(".cart-price").textContent.replace("$", ""));
        const quantity = parseInt(cartBox.querySelector(".number").textContent);
        total         += price * quantity;
    });

    totalPriceElement.textContent = `$${total.toFixed(2)}`;
};

let cartItemCount = 0;

const updateCartCount = change => {
    const cartItemCountBadge = document.querySelector(".cart-item-count");
    cartItemCount           += change;

    if (cartItemCount > 0) {
        cartItemCountBadge.style.visibility = "visible";
        cartItemCountBadge.textContent      = cartItemCount;
    } else {
        cartItemCountBadge.style.visibility = "hidden";
        cartItemCountBadge.textContent      = "";
    }
};

const buyNowButton = document.querySelector(".btn-buy");

buyNowButton.addEventListener("click", () => {
    const cartBoxes = cartContent.querySelectorAll(".cart-box");

    if (cartBoxes.length < 3) {
        alert("You need at least 3 products in your cart to proceed to checkout.");
        return;
    }

    window.location.href = "../pages/card.php";
});