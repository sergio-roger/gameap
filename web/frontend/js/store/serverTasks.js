import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc'
import axios from '../config/axios'
import { useServerStore } from './server'

dayjs.extend(utc)

export const useServerTasksStore = defineStore('serverTasks', () => {
    // State
    const tasks = ref([])
    const apiProcesses = ref(0)

    // Getters
    const loading = computed(() => apiProcesses.value > 0)

    // Actions
    async function fetchTasks() {
        const serverStore = useServerStore()
        if (serverStore.serverId <= 0) {
            return
        }

        apiProcesses.value++
        try {
            const response = await axios.get('/api/servers/' + serverStore.serverId + '/tasks')
            tasks.value = response.data.map(task => ({
                ...task,
                execute_date: dayjs.utc(task.execute_date).local().format('YYYY-MM-DD HH:mm:ss')
            }))
        } finally {
            apiProcesses.value--
        }
    }

    async function storeTask(task) {
        const serverStore = useServerStore()

        const storeTaskData = {
            ...task,
            execute_date: dayjs(task.execute_date).utc().format('YYYY-MM-DD HH:mm:ss')
        }

        apiProcesses.value++
        try {
            const response = await axios.post('/api/servers/' + serverStore.serverId + '/tasks', storeTaskData)
            task.id = response.data.serverTaskId
            tasks.value.push(task)
        } finally {
            apiProcesses.value--
        }
    }

    async function updateTask(taskIndex, task) {
        const serverStore = useServerStore()
        const taskId = tasks.value[taskIndex].id

        const storeTaskData = {
            ...task,
            execute_date: dayjs(task.execute_date).utc().format('YYYY-MM-DD HH:mm:ss')
        }

        apiProcesses.value++
        try {
            await axios.put('/api/servers/' + serverStore.serverId + '/tasks/' + taskId, storeTaskData)
            tasks.value[taskIndex] = { ...tasks.value[taskIndex], ...task }
        } finally {
            apiProcesses.value--
        }
    }

    async function destroyTask(taskIndex) {
        const serverStore = useServerStore()
        if (serverStore.serverId <= 0) {
            return
        }

        const taskId = tasks.value[taskIndex].id

        apiProcesses.value++
        try {
            await axios.delete('/api/servers/' + serverStore.serverId + '/tasks/' + taskId)
            tasks.value.splice(taskIndex, 1)
        } finally {
            apiProcesses.value--
        }
    }

    return {
        // State
        tasks,
        apiProcesses,

        // Getters
        loading,

        // Actions
        fetchTasks,
        storeTask,
        updateTask,
        destroyTask,
    }
})
