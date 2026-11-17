function api(path, options = {}) {

  return fetch(API_URL + path, { credentials: 'include', ...options });
}

async function requireLogin() {
  try {
    const res = await api('/api/me');
    if (!res.ok) throw new Error('not logged in');
    const data = await res.json();
    document.getElementById('app').hidden = false;
    return data;
  } catch {
    location.replace('index.html');
  }
}

function setupLogout() {
  document.getElementById('logout').addEventListener('click', async e => {
    e.preventDefault();
    try {
      await api('/api/logout', { method: 'POST' });
    } catch {}
    location.replace('index.html');
  });
}
