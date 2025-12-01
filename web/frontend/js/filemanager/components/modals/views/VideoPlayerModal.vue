<template>
    <div class="fm-modal-video-player">
        <div class="text-sm text-stone-500 mb-2">{{ videoFile?.basename }}</div>
        <video ref="fmVideo" controls />
    </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import Plyr from 'plyr'
import { useFileManagerStore } from '../../../stores/useFileManagerStore.js'
import { useSettingsStore } from '../../../stores/useSettingsStore.js'
import { useTranslate } from '../../../composables/useTranslate.js'
import { useModal } from '../../../composables/useModal.js'

const fm = useFileManagerStore()
const settings = useSettingsStore()
const { lang } = useTranslate()
const { hideModal } = useModal()

const fmVideo = ref(null)
const player = ref(null)

const selectedDisk = computed(() => fm.selectedDisk)
const videoFile = computed(() => fm.selectedItems[0])

onMounted(() => {
    player.value = new Plyr(fmVideo.value)

    player.value.source = {
        type: 'video',
        title: videoFile.value.filename,
        sources: [
            {
                src: `${settings.baseUrl}/stream-file?disk=${selectedDisk.value}&path=${encodeURIComponent(videoFile.value.path)}`,
                type: `video/${videoFile.value.extension}`,
            },
        ],
    }
})

onBeforeUnmount(() => {
    if (player.value) {
        player.value.destroy()
    }
})

defineExpose({
    footerButtons: computed(() => []),
})
</script>

<style lang="scss">
@import 'plyr/plyr.scss';
</style>
