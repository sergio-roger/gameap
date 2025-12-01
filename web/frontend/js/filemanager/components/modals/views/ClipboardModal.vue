<template>
    <div>
        <template v-if="clipboard.type">
            <div class="flex justify-between items-center mb-3">
                <div class="truncate">
                    <n-tag>
                        <template #icon>
                            <i class="fa-solid fa-hard-drive"></i>
                        </template>
                        {{ clipboard.disk }}
                    </n-tag>
                </div>
                <div class="text-stone-500">
                    <span :title="`${lang.clipboard.actionType} - ${lang.clipboard[clipboard.type]}`">
                        <i v-if="clipboard.type === 'copy'" class="fa-regular fa-copy" />
                        <i v-else class="fa-solid fa-scissors" />
                    </span>
                </div>
            </div>
            <n-divider />
            <div
                class="flex justify-between items-center py-1"
                v-for="(dir, index) in directories"
                :key="`d-${index}`"
            >
                <div class="truncate">
                    <span><i class="fa-regular fa-folder mr-2"></i>{{ dir.name }}</span>
                </div>
                <div>
                    <n-button
                        quaternary
                        circle
                        size="small"
                        :title="lang.btn.delete"
                        @click="deleteItem('directories', dir.path)"
                    >
                        <template #icon>
                            <i class="fa-solid fa-xmark"></i>
                        </template>
                    </n-button>
                </div>
            </div>
            <div class="flex justify-between items-center py-1" v-for="(file, index) in files" :key="`f-${index}`">
                <div class="truncate">
                    <span><i :class="[file.icon, 'mr-2']" />{{ file.name }}</span>
                </div>
                <div>
                    <n-button
                        quaternary
                        circle
                        size="small"
                        :title="lang.btn.delete"
                        @click="deleteItem('files', file.path)"
                    >
                        <template #icon>
                            <i class="fa-solid fa-xmark"></i>
                        </template>
                    </n-button>
                </div>
            </div>
        </template>
        <template v-else>
            <span>{{ lang.clipboard.none }}</span>
        </template>
    </div>
</template>

<script setup>
import { computed } from 'vue'
import { useFileManagerStore } from '../../../stores/useFileManagerStore.js'
import { useTranslate } from '../../../composables/useTranslate.js'
import { useHelper } from '../../../composables/useHelper.js'
import { useModal } from '../../../composables/useModal.js'

const fm = useFileManagerStore()
const { lang } = useTranslate()
const { extensionToIcon } = useHelper()
const { hideModal } = useModal()

const clipboard = computed(() => fm.clipboard)

const directories = computed(() =>
    fm.clipboard.directories.map((item) => ({
        path: item,
        name: item.split('/').slice(-1)[0],
    }))
)

const files = computed(() =>
    fm.clipboard.files.map((item) => {
        const name = item.split('/').slice(-1)[0]
        return {
            path: item,
            name,
            icon: extensionToIcon(name.split('.').slice(-1)[0]),
        }
    })
)

function deleteItem(type, path) {
    fm.truncateClipboard({ type, path })
}

function resetClipboardAction() {
    fm.resetClipboard()
}

defineExpose({
    footerButtons: computed(() => [
        { label: lang.value.btn.clear, color: 'red', icon: 'fa-solid fa-broom', action: resetClipboardAction, disabled: !clipboard.value.type },
        { label: lang.value.btn.cancel, color: 'black', icon: 'fa-solid fa-xmark', action: hideModal },
    ]),
})
</script>
