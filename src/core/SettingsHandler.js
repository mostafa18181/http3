// SettingsHandler.js

class SettingsHandler {
    constructor(dynamicTable) {
        this.dynamicTable = dynamicTable; // ارجاع به جدول دینامیک
    }

    /**
     * Handle incoming SETTINGS frame and update configuration accordingly.
     * @param {Object} settings - The SETTINGS object containing configuration options.
     */
    handleSettingsFrame(settings) {
        if (settings.maxTableSize !== undefined) {
            // به‌روزرسانی حداکثر اندازه جدول دینامیک
            this.dynamicTable.maxSize = settings.maxTableSize;
            console.log(`Dynamic table size updated to: ${settings.maxTableSize}`);
        }

        if (settings.enableQPACK !== undefined) {
            // فعال یا غیرفعال کردن QPACK (اختیاری)
            console.log(`QPACK support: ${settings.enableQPACK ? 'Enabled' : 'Disabled'}`);
        }

        // افزودن تنظیمات دیگر در صورت نیاز
    }
}

// خروجی کلاس SettingsHandler به عنوان ماژول
module.exports = SettingsHandler;
