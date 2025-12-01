<template>
    <div class="flex flex-col">
        <div v-if="showCropperModule" class="text-sm text-stone-500 mb-2">
            {{ lang.modal.cropper.title }} - {{ selectedItem?.basename }}
        </div>
        <div v-else class="text-sm text-stone-500 mb-2">
            {{ selectedItem?.basename }}
        </div>
        <div class="flex text-center justify-center items-center min-h-[200px]">
            <template v-if="showCropperModule">
                <cropper-module :imgSrc="imgSrc" :maxHeight="maxHeight" @closeCropper="closeCropper" />
            </template>
            <template v-else>
                <n-spin v-if="!imgSrc" size="large" />
                <img
                    v-else
                    :src="imgSrc"
                    :alt="selectedItem?.basename"
                    :style="{ 'max-height': maxHeight + 'px' }"
                    class="max-w-full"
                />
            </template>
        </div>
    </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import CropperModule from '../additions/CropperModule.vue'
import { useFileManagerStore } from '../../../stores/useFileManagerStore.js'
import { useSettingsStore } from '../../../stores/useSettingsStore.js'
import { useTranslate } from '../../../composables/useTranslate.js'
import { useModal } from '../../../composables/useModal.js'
import GET from '../../../http/get.js'

const fm = useFileManagerStore()
const settings = useSettingsStore()
const { lang } = useTranslate()
const { hideModal } = useModal()

const showCropperModule = ref(false)
const imgSrc = ref(null)

const auth = computed(() => settings.authHeader)
const selectedDisk = computed(() => fm.selectedDisk)
const selectedItem = computed(() => fm.selectedItems[0])

const canCropImage = computed(() => {
    if (!selectedItem.value?.extension) return false
    return settings.cropExtensions.includes(selectedItem.value.extension.toLowerCase())
})

const maxHeight = computed(() => {
    return Math.min(window.innerHeight - 300, 600)
})

function canCrop(extension) {
    return settings.cropExtensions.includes(extension.toLowerCase())
}

function closeCropper() {
    showCropperModule.value = false
    loadImage()
}

function loadImage() {
    if (auth.value) {
        GET.preview(selectedDisk.value, selectedItem.value.path).then((response) => {
            const mimeType = response.headers['content-type'].toLowerCase()
            const imgBase64 = btoa(String.fromCharCode.apply(null, new Uint8Array(response.data)))
            imgSrc.value = `data:${mimeType};base64,${imgBase64}`
        })
    } else {
        imgSrc.value = `${settings.baseUrl}preview?disk=${selectedDisk.value}&path=${encodeURIComponent(selectedItem.value.path)}&v=${selectedItem.value.timestamp}`
    }
}

function openCropper() {
    showCropperModule.value = true
}

onMounted(() => {
    loadImage()
})

defineExpose({
    footerButtons: computed(() => {
        if (showCropperModule.value) {
            return []
        }
        const buttons = []
        if (canCropImage.value) {
            buttons.push({ label: lang.value.modal.cropper.title, color: 'green', icon: 'fa-solid fa-crop', action: openCropper })
        }
        buttons.push({ label: lang.value.btn.cancel, color: 'black', icon: 'fa-solid fa-xmark', action: hideModal })
        return buttons
    }),
})
</script>
