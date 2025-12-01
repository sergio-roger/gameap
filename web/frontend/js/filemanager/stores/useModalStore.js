import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useModalStore = defineStore('fm-modal', () => {
    const showModal = ref(false)
    const modalName = ref(null)

    function setModalState({ show, modalName: name }) {
        showModal.value = show
        modalName.value = name
    }

    function clearModal() {
        showModal.value = false
        modalName.value = null
    }

    return {
        showModal,
        modalName,
        setModalState,
        clearModal,
    }
})
