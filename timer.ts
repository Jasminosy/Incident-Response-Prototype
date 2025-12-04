export function setupTimer() {
  const alertStartInput = document.getElementById('alert-start') as HTMLInputElement;
  const elapsedTimeElement = document.getElementById('elapsed-time');

  if (!alertStartInput || !elapsedTimeElement) {
    console.error('Timer elements not found!');
    return;
  }

  let timerInterval: number;

  /**
   * Formatiert eine Zahl zweistellig, indem bei Bedarf eine führende Null hinzugefügt wird.
   * @param num Die zu formatierende Zahl.
   */
  function padTo2Digits(num: number): string {
    return num.toString().padStart(2, '0');
  }

  /**
   * Formatiert ein Date-Objekt in das für datetime-local benötigte Format.
   * @param date Das zu formatierende Date-Objekt.
   */
  function formatDateTimeForInput(date: Date): string {
    const year = date.getFullYear();
    const month = padTo2Digits(date.getMonth() + 1);
    const day = padTo2Digits(date.getDate());
    const hours = padTo2Digits(date.getHours());
    const minutes = padTo2Digits(date.getMinutes());
    const seconds = padTo2Digits(date.getSeconds());

    return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
  }

  /**
   * Aktualisiert die Anzeige der verstrichenen Zeit.
   */
  function updateElapsedTime() {
    const startTime = new Date(alertStartInput.value);
    const now = new Date();
    const difference = now.getTime() - startTime.getTime();

    if (difference < 0) {
      elapsedTimeElement!.textContent = '00:00:00';
      return;
    }

    const hours = Math.floor(difference / (1000 * 60 * 60));
    const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((difference % (1000 * 60)) / 1000);

    elapsedTimeElement!.textContent = `${padTo2Digits(hours)}:${padTo2Digits(minutes)}:${padTo2Digits(seconds)}`;
  }

  // Setzt die aktuelle Zeit als Standardwert und startet den Timer
  const now = new Date();
  alertStartInput.value = formatDateTimeForInput(now);
  updateElapsedTime();
  timerInterval = window.setInterval(updateElapsedTime, 1000);

  // Wenn der Benutzer die Zeit manuell ändert, wird der Timer neu gestartet
  alertStartInput.addEventListener('change', () => {
    clearInterval(timerInterval);
    updateElapsedTime();
    timerInterval = window.setInterval(updateElapsedTime, 1000);
  });
}