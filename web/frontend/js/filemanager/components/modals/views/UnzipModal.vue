<template>
    <div>
        <div class="flex items-center gap-4 mb-4">
            <div>
                <strong>{{ lang.modal.unzip.fieldRadioName }}</strong>
            </div>
            <n-radio-group v-model:value="createFolder">
                <n-radio :value="false">{{ lang.modal.unzip.fieldRadio1 }}</n-radio>
                <n-radio :value="true">{{ lang.modal.unzip.fieldRadio2 }}</n-radio>
            </n-radio-group>
        </div>
        <n-divider />
        <div v-if="createFolder" class="mb-3">
            <label for="fm-folder-name" class="block mb-2">{{ lang.modal.unzip.fieldName }}</label>
            <n-input
                id="fm-folder-name"
                ref="folderInput"
                v-model:value="directoryName"
                :status="directoryExist ? 'error' : undefined"
                @keyup="validateDirName"
                @keyup.enter="submitActive && unpackArchive()"
            />
            <div v-if="directoryExist" class="text-red-500 text-sm mt-1">
                {{ lang.modal.unzip.fieldFeedback }}
            </div>
        </div>
        <span v-else class="text-orange-500">{{ lang.modal.unzip.warning }}</span>
    </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useFileManagerStore } from '../../../stores/useFileManagerStore.js'
import { useTranslate } from '../../../composables/useTranslate.js'
import { useModal } from '../../../composables/useModal.js'

const fm = useFileManagerStore()
const { lang } = useTranslate()
const { activeManager, hideModal } = useModal()

const createFolder = ref(false)
const directoryName = ref('')
const directoryExist = ref(false)
const folderInput = ref(null)

const submitActive = computed(() => {
    if (createFolder.value) {
        return directoryName.value && !directoryExist.value
    }
    return true
})

watch(createFolder, (newVal) => {
    if (newVal) {
        setTimeout(() => folderInput.value?.focus(), 0)
    }
})

function validateDirName() {
    if (directoryName.value) {
        directoryExist.value = fm.directoryExist(activeManager.value, directoryName.value)
    } else {
        directoryExist.value = false
    }
}

function unpackArchive() {
    fm.unzip(createFolder.value ? directoryName.value : null).then(() => {
        hideModal()
    })
}

defineExpose({
    footerButtons: computed(() => [
        { label: lang.value.btn.submit, color: 'green', icon: 'fa-solid fa-file-zipper', action: unpackArchive, disabled: !submitActive.value },
        { label: lang.value.btn.cancel, color: 'black', icon: 'fa-solid fa-xmark', action: hideModal },
    ]),
})
</script>
