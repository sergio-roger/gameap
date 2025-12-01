<template>
    <div class="fm-modal-audio-player">
        <audio ref="fmAudio" controls />
        <n-divider />
        <div
            class="flex justify-between items-center py-2 px-2 rounded cursor-pointer"
            :class="playingIndex === index ? 'bg-stone-100 dark:bg-stone-800' : 'hover:bg-stone-50 dark:hover:bg-stone-900'"
            v-for="(item, index) in audioFiles"
            :key="index"
        >
            <div class="truncate flex-1">
                <span class="text-stone-400 mr-2">{{ index }}.</span>
                {{ item.basename }}
            </div>
            <template v-if="playingIndex === index">
                <n-button quaternary circle @click="togglePlay()">
                    <template #icon>
                        <i v-if="status === 'playing'" class="fa-solid fa-pause" />
                        <i v-else class="fa-solid fa-play text-blue-500" />
                    </template>
                </n-button>
            </template>
            <template v-else>
                <n-button quaternary circle @click="selectTrack(index)">
                    <template #icon>
                        <i class="fa-solid fa-play" />
                    </template>
                </n-button>
            </template>
        </div>
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

const fmAudio = ref(null)
const player = ref(null)
const playingIndex = ref(0)
const status = ref('paused')

const selectedDisk = computed(() => fm.selectedDisk)
const audioFiles = computed(() => fm.selectedItems)

function setSource(index) {
    player.value.source = {
        type: 'audio',
        title: audioFiles.value[index].filename,
        sources: [
            {
                src: `${settings.baseUrl}/stream-file?disk=${selectedDisk.value}&path=${encodeURIComponent(audioFiles.value[index].path)}`,
                type: `audio/${audioFiles.value[index].extension}`,
            },
        ],
    }
}

function selectTrack(index) {
    if (player.value.playing) {
        player.value.stop()
    }
    setSource(index)
    player.value.play()
    playingIndex.value = index
}

function togglePlay() {
    player.value.togglePlay()
}

onMounted(() => {
    player.value = new Plyr(fmAudio.value, {
        speed: {
            selected: 1,
            options: [0.5, 1, 1.5],
        },
    })

    setSource(playingIndex.value)

    player.value.on('play', () => {
        status.value = 'playing'
    })

    player.value.on('pause', () => {
        status.value = 'paused'
    })

    player.value.on('ended', () => {
        if (audioFiles.value.length > playingIndex.value + 1) {
            selectTrack(playingIndex.value + 1)
        }
    })
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
