<template>
    <div>
        <label for="fm-zip-name" class="block mb-2">{{ lang.modal.zip.fieldName }}</label>
        <n-input-group class="mb-3">
            <n-input
                id="fm-zip-name"
                ref="archiveInput"
                v-model:value="archiveName"
                :status="archiveExist ? 'error' : undefined"
                @keyup="validateArchiveName"
                @keyup.enter="submitActive && createArchive()"
            />
            <n-input-group-label>.zip</n-input-group-label>
        </n-input-group>
        <div v-if="archiveExist" class="text-red-500 text-sm mb-3">
            {{ lang.modal.zip.fieldFeedback }}
        </div>
        <n-divider />
        <selected-file-list />
    </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import SelectedFileList from '../additions/SelectedFileList.vue'
import { useFileManagerStore } from '../../../stores/useFileManagerStore.js'
import { useTranslate } from '../../../composables/useTranslate.js'
import { useModal } from '../../../composables/useModal.js'

const fm = useFileManagerStore()
const { lang } = useTranslate()
const { activeManager, hideModal } = useModal()

const archiveName = ref('')
const archiveExist = ref(false)
const archiveInput = ref(null)

const submitActive = computed(() => archiveName.value && !archiveExist.value)

onMounted(() => {
    archiveInput.value?.focus()
})

function validateArchiveName() {
    if (archiveName.value) {
        archiveExist.value = fm.fileExist(activeManager.value, `${archiveName.value}.zip`)
    } else {
        archiveExist.value = false
    }
}

function createArchive() {
    fm.zip(`${archiveName.value}.zip`).then(() => {
        hideModal()
    })
}

defineExpose({
    footerButtons: computed(() => [
        { label: lang.value.btn.submit, color: 'green', icon: 'fa-solid fa-file-zipper', action: createArchive, disabled: !submitActive.value },
        { label: lang.value.btn.cancel, color: 'black', icon: 'fa-solid fa-xmark', action: hideModal },
    ]),
})
</script>
