import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from '../config/axios'

export const useGameStore = defineStore('game', () => {
    // State
    const apiProcesses = ref(0)
    const gameCode = ref('')
    const game = ref({})
    const mods = ref([])

    // Getters
    const loading = computed(() => apiProcesses.value > 0)

    // Actions
    function setGameCode(code) {
        gameCode.value = code
    }

    async function fetchGame() {
        apiProcesses.value++
        try {
            const response = await axios.get('/api/games/' + gameCode.value)
            game.value = response.data
        } finally {
            apiProcesses.value--
        }
    }

    async function fetchMods() {
        apiProcesses.value++
        try {
            const response = await axios.get('/api/games/' + gameCode.value + '/mods')
            mods.value = response.data
        } finally {
            apiProcesses.value--
        }
    }

    async function saveGame(gameData) {
        apiProcesses.value++
        try {
            await axios.put('/api/games/' + gameCode.value, gameData)
        } finally {
            apiProcesses.value--
        }
    }

    return {
        // State
        apiProcesses,
        gameCode,
        game,
        mods,

        // Getters
        loading,

        // Actions
        setGameCode,
        fetchGame,
        fetchMods,
        saveGame,
    }
})
