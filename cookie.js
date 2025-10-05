// 设置一个没有任何用处的cookie
function setUselessCookie() {
    // 设置一个没有任何实际用途的cookie
    // 这个cookie不存储任何有意义的信息，只是为了演示
    const cookieName = "useless_cookie";
    const cookieValue = "this_is_completely_useless_" + Date.now();
    const expirationDays = 7; // 7天后过期
    
    const d = new Date();
    d.setTime(d.getTime() + (expirationDays * 24 * 60 * 60 * 1000));
    const expires = "expires=" + d.toUTCString();
    
    // 设置cookie
    document.cookie = `${cookieName}=${cookieValue}; ${expires}; path=/`;
    
    console.log("无用Cookie已设置:", {
        name: cookieName,
        value: cookieValue,
        expires: d.toUTCString()
    });
    
    return {
        name: cookieName,
        value: cookieValue,
        expires: d.toUTCString()
    };
}

// 获取cookie值
function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length);
    }
    return null;
}

// 检查无用cookie是否存在
function checkUselessCookie() {
    const cookieValue = getCookie("useless_cookie");
    if (cookieValue) {
        console.log("无用Cookie存在，值为:", cookieValue);
        return {
            exists: true,
            value: cookieValue
        };
    } else {
        console.log("无用Cookie不存在");
        return {
            exists: false,
            value: null
        };
    }
}

// 删除无用cookie
function deleteUselessCookie() {
    document.cookie = "useless_cookie=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    console.log("无用Cookie已删除");
    return true;
}

// 示例使用
// 设置无用cookie
setUselessCookie();

// 检查cookie是否存在
setTimeout(() => {
    checkUselessCookie();
}, 100);

// 5秒后删除cookie（可选）
// setTimeout(() => {
//     deleteUselessCookie();
// }, 5000);

// 导出函数供其他模块使用（如果使用模块系统）
// export { setUselessCookie, checkUselessCookie, deleteUselessCookie };