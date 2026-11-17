
const PROD_API = 'https://prjc1-api.onrender.com';

const API_URL = ['localhost', '127.0.0.1'].includes(location.hostname)
  ? 'http://localhost:3000'
  : PROD_API;
