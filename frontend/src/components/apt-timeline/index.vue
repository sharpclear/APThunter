<script setup lang="ts">
import dayjs from 'dayjs'

defineOptions({
  name: 'AptTimeline',
})

// 事件接口
export interface AptEvent {
  id: string | number
  date: string // YYYY-MM-DD
  title: string
  description?: string
  type?: 'major' | 'normal' // major: 重要事件（实心盾形），normal: 普通事件（圆形轮廓）
  organization?: string
}

interface Props {
  events: AptEvent[]
  startDate?: string // 开始日期，默认为2024-09-01
  endDate?: string // 结束日期，默认为2025-12-31
  showEventsList?: boolean // 是否显示事件列表
}

interface Emits {
  (e: 'event-click', event: AptEvent): void
}

const props = withDefaults(defineProps<Props>(), {
  events: () => [],
  startDate: '2024-09-01',
  endDate: '2025-12-31',
  showEventsList: false,
})

const emit = defineEmits<Emits>()

// 处理事件点击
function handleEventClick(event: AptEvent) {
  emit('event-click', event)
}

// 计算时间范围
const start = dayjs(props.startDate)
const end = dayjs(props.endDate)
const totalDays = end.diff(start, 'day')

// 生成时间刻度点（每个月）
const timePoints = computed(() => {
  const points: Array<{ date: dayjs.Dayjs; label: string; year: number; month: number }> = []
  let current = start.startOf('month')
  
  while (current.isBefore(end) || current.isSame(end, 'month')) {
    const monthLabel = `${current.month() + 1}月`
    points.push({
      date: current,
      label: monthLabel,
      year: current.year(),
      month: current.month() + 1,
    })
    current = current.add(1, 'month')
  }
  
  return points
})

// 获取事件在时间轴上的位置（百分比）
function getEventPosition(eventDate: string): number {
  const event = dayjs(eventDate)
  if (event.isBefore(start)) return 0
  if (event.isAfter(end)) return 100
  const daysFromStart = event.diff(start, 'day')
  return Math.max(0, Math.min(100, (daysFromStart / totalDays) * 100))
}

// 检查是否为重要月份（需要显示月份标签）- 显示3月、6月、9月、12月
const importantMonths = computed(() => {
  const months = new Set<number>()
  timePoints.value.forEach((point, index) => {
    // 显示每季度月份：3月、6月、9月、12月，以及开始和结束月份
    if (index === 0 || index === timePoints.value.length - 1 || [3, 6, 9, 12].includes(point.month)) {
      months.add(index)
    }
  })
  return months
})

// 获取年份标签位置
const yearPositions = computed(() => {
  const positions: Array<{ year: number; position: number }> = []
  const yearMap = new Map<number, number>()
  
  timePoints.value.forEach((point, index) => {
    if (!yearMap.has(point.year)) {
      yearMap.set(point.year, index)
    }
  })
  
  yearRange.value.forEach(year => {
    const index = yearMap.get(year)!
    const position = timePoints.value.length > 1 
      ? (index / (timePoints.value.length - 1)) * 100 
      : 0
    positions.push({ year, position })
  })
  
  return positions
})

// 获取事件数据，按日期排序
const sortedEvents = computed(() => {
  return [...props.events].sort((a, b) => {
    return dayjs(a.date).valueOf() - dayjs(b.date).valueOf()
  })
})

// 获取当前年份范围
const yearRange = computed(() => {
  const years = new Set<number>()
  timePoints.value.forEach(point => {
    years.add(point.year)
  })
  return Array.from(years).sort()
})
</script>

<template>
  <div class="apt-timeline-container">
    <!-- 年份标签行 -->
    <div class="timeline-years">
      <template v-for="yearPos in yearPositions" :key="yearPos.year">
        <div
          class="year-label"
          :style="{
            left: `${yearPos.position}%`,
            transform: yearPos.position === 0 ? 'translateX(0)' : yearPos.position === 100 ? 'translateX(-100%)' : 'translateX(-50%)',
          }"
        >
          {{ yearPos.year }}
        </div>
      </template>
    </div>

    <!-- 时间轴主体 -->
    <div class="timeline-wrapper">
      <!-- 时间轴线 -->
      <div class="timeline-line" />
      
      <!-- 时间刻度点 -->
      <template v-for="(_, index) in timePoints" :key="index">
        <div
          class="time-point"
          :class="{ 'important-month': importantMonths.has(index) }"
          :style="{ left: `${(index / (timePoints.length - 1)) * 100}%` }"
        >
          <div class="time-dot" />
        </div>
      </template>

      <!-- 月份标签 -->
      <div class="timeline-months">
        <template v-for="(point, index) in timePoints" :key="index">
          <div
            v-if="importantMonths.has(index)"
            class="month-label"
            :style="{
              left: `${(index / (timePoints.length - 1)) * 100}%`,
              transform: index === 0 ? 'translateX(0)' : index === timePoints.length - 1 ? 'translateX(-100%)' : 'translateX(-50%)',
            }"
          >
            {{ point.label }}
          </div>
        </template>
      </div>

      <!-- 事件标记 -->
      <template v-for="event in sortedEvents" :key="event.id">
        <div
          class="event-marker"
          :class="{
            'event-major': event.type === 'major',
            'event-normal': event.type !== 'major',
          }"
          :style="{ left: `${getEventPosition(event.date)}%` }"
          :title="`${event.title}${event.organization ? ' - ' + event.organization : ''}`"
          @click="handleEventClick(event)"
        >
          <div v-if="event.type === 'major'" class="event-shield">
            <div class="shield-content" />
          </div>
          <div v-else class="event-circle" />
          <!-- 事件标题提示 -->
          <div class="event-tooltip">{{ event.title }}</div>
        </div>
      </template>
    </div>

    <!-- 事件列表（可选，显示在时间轴下方） -->
    <div v-if="sortedEvents.length > 0 && props.showEventsList" class="events-list">
      <div
        v-for="event in sortedEvents"
        :key="event.id"
        class="event-item"
      >
        <div class="event-date">{{ dayjs(event.date).format('YYYY-MM-DD') }}</div>
        <div class="event-title">{{ event.title }}</div>
        <div v-if="event.description" class="event-description">{{ event.description }}</div>
      </div>
    </div>
  </div>
</template>

<style scoped lang="less">
.apt-timeline-container {
  width: 100%;
  padding: 20px 12px;
  background: #ffffff;
  border-radius: 4px;
}

.timeline-years {
  position: relative;
  height: 32px;
  margin-bottom: 8px;
  
  .year-label {
    position: absolute;
    top: 0;
    font-weight: 600;
    font-size: 14px;
    color: rgba(0, 0, 0, 0.85);
    white-space: nowrap;
  }
}

.timeline-wrapper {
  position: relative;
  height: 120px;
  margin: 16px 0;
  padding: 0 8px;
}

.timeline-line {
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(to right, #d9d9d9 0%, #d9d9d9 100%);
  transform: translateY(-50%);
}

.time-point {
  position: absolute;
  top: 50%;
  transform: translate(-50%, -50%);
  z-index: 1;
  
  .time-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #bfbfbf;
    border: none;
  }
  
  &.important-month .time-dot {
    width: 8px;
    height: 8px;
    background: #8c8c8c;
  }
}

.timeline-months {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  height: 24px;
  
  .month-label {
    position: absolute;
    font-size: 12px;
    color: rgba(0, 0, 0, 0.65);
    white-space: nowrap;
  }
}

.event-marker {
  position: absolute;
  top: 50%;
  transform: translate(-50%, -50%);
  z-index: 10;
  cursor: pointer;
  transition: all 0.3s;
  
  &:hover {
    transform: translate(-50%, -50%) scale(1.3);
    z-index: 20;
    
    .event-tooltip {
      opacity: 1;
      visibility: visible;
      transform: translate(-50%, -100%) translateY(-8px);
    }
  }
}

.event-tooltip {
  position: absolute;
  bottom: 100%;
  left: 50%;
  transform: translate(-50%, 0);
  background: rgba(0, 0, 0, 0.85);
  color: #ffffff;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  white-space: nowrap;
  pointer-events: none;
  opacity: 0;
  visibility: hidden;
  transition: all 0.3s;
  margin-bottom: 4px;
  
  &::after {
    content: '';
    position: absolute;
    top: 100%;
    left: 50%;
    transform: translateX(-50%);
    border: 4px solid transparent;
    border-top-color: rgba(0, 0, 0, 0.85);
  }
}

.event-circle {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  border: 2px solid #52c41a;
  background: #ffffff;
  box-shadow: 0 1px 4px rgba(82, 196, 26, 0.4);
}

.event-shield {
  width: 18px;
  height: 22px;
  position: relative;
  
  &::before {
    content: '';
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 0;
    height: 0;
    border-left: 9px solid transparent;
    border-right: 9px solid transparent;
    border-top: 7px solid #52c41a;
  }
  
  .shield-content {
    position: absolute;
    top: 7px;
    left: 50%;
    transform: translateX(-50%);
    width: 18px;
    height: 15px;
    background: #52c41a;
    border-radius: 0 0 3px 3px;
    box-shadow: 0 2px 6px rgba(82, 196, 26, 0.5);
  }
}

.events-list {
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid #f0f0f0;
  
  .event-item {
    padding: 12px 0;
    border-bottom: 1px solid #fafafa;
    
    &:last-child {
      border-bottom: none;
    }
    
    .event-date {
      font-size: 12px;
      color: rgba(0, 0, 0, 0.45);
      margin-bottom: 4px;
    }
    
    .event-title {
      font-size: 14px;
      font-weight: 500;
      color: rgba(0, 0, 0, 0.85);
      margin-bottom: 4px;
    }
    
    .event-description {
      font-size: 12px;
      color: rgba(0, 0, 0, 0.65);
      line-height: 1.6;
    }
  }
}
</style>

