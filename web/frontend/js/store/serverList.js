import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from '../config/axios'

export const useServerListStore = defineStore('serverList', () => {
    // State
    const servers = ref([])
    const summary = ref({
        total: 0,
        online: 0,
        offline: 0,
    })
    const apiProcesses = ref(0)

    // Getters
    const loading = computed(() => apiProcesses.value > 0)

    // Actions
    async function fetchServersByFilter(filter) {
        apiProcesses.value++
        try {
            const response = await axios.get('/api/servers')
            servers.value = response.data
        } catch (error) {
            if (error.__CANCEL__) {
                return
            }
            throw error
        } finally {
            apiProcesses.value--
        }
    }

    // From legacy servers.js - fetches servers optionally filtered by node ID
    async function fetchServersByNode(nodeId = null) {
        apiProcesses.value++
        try {
            let url = '/api/servers'
            if (nodeId) {
                url = '/api/servers?filter[ds_id]=' + nodeId + '&append=full_path'
            }
            const response = await axios.get(url)
            servers.value = response.data
        } catch (error) {
            if (error.__CANCEL__) {
                return
            }
            throw error
        } finally {
            apiProcesses.value--
        }
    }

    async function fetchServersSummary() {
        apiProcesses.value++
        try {
            const response = await axios.get('/api/servers/summary')
            summary.value = response.data
        } catch (error) {
            if (error.__CANCEL__) {
                return
            }
            throw error
        } finally {
            apiProcesses.value--
        }
    }

    async function create(server) {
        apiProcesses.value++
        try {
            await axios.post('/api/servers', server)
        } catch (error) {
            if (error.__CANCEL__) {
                return
            }
            throw error
        } finally {
            apiProcesses.value--
        }
    }

    async function deleteById(id, deleteFiles) {
        apiProcesses.value++
        try {
            await axios.post(
                '/api/servers/' + id,
                {delete_files: deleteFiles},
                {headers: {'X-Http-Method-Override': 'DELETE'}},
            )
        } catch (error) {
            if (error.__CANCEL__) {
                return
            }
            throw error
        } finally {
            apiProcesses.value--
        }
    }

    return {
        // State
        servers,
        summary,
        apiProcesses,

        // Getters
        loading,

        // Actions
        fetchServersByFilter,
        fetchServersByNode,
        fetchServersSummary,
        create,
        deleteById,
    }
})
