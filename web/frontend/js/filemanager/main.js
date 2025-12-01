import { createApp } from 'vue';

import './style.css'

// App
import App from './FileManager.vue';

// create new store
const store = createStore({
    strict: import.meta.env.DEV,
    modules: { fm },
});

window.fm = createApp(App).mount('#fm');
