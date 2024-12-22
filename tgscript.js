   const apiUrl = 'https://vtjvlad.ddns.net'
	
		 // Проверка, если Telegram Web App доступен
    if (window.Telegram.WebApp) {
        const tg = window.Telegram.WebApp;
        
        // Инициализируем Telegram Web App
        tg.ready();
        
        // Получаем информацию о пользователе из Telegram
        const user = tg.initDataUnsafe?.user;
        
				if (user) {
    // Отправить данные пользователя на сервер
		async function register(event) {
			event.preventDefault();
			
			const tgId = ${user.id};
			const username = ${user.username};
			const Name = ${user.first_name};
			
   const response = await fetch('${apiUrl}/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tgId, username, Name }),
    });
    
		if (response.ok) {
            alert('Well done');
           console.log('Logged in!');
        } else {
            console.error('Ошибка umавторизации');
        }
    });
}
        } else {
            alert('Ошибка авторизации через Telegram.');
        }
    } else {
        alert('Telegram Web App не поддерживается в этом браузере.');
    }