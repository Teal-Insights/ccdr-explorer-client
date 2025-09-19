;(function () {
  'use strict'

  function initResultsCarousel(container) {
    if (!container || (container.matches && !container.matches('.text-carousel[data-results-carousel]')) || container.__resultsCarouselInitialized) return
    container.__resultsCarouselInitialized = true

    var content = container.querySelector('.carousel-content')
    var slides = Array.prototype.slice.call(container.querySelectorAll('.text-slide'))
    var prevBtn = container.querySelector('[data-action="prev"]')
    var nextBtn = container.querySelector('[data-action="next"]')
    var indicator = container.querySelector('[data-role="indicator"]')

    var currentIndex = 0
    var totalItems = slides.length
    var overflowingStates = []
    try { console.debug('[results-carousel] init', { totalItems: totalItems, container: container }) } catch (e) {}

    function update() {
      var translateX = -currentIndex * 100
      if (content) {
        content.style.transform = 'translateX(' + translateX + '%)'
      }

      if (indicator) {
        indicator.textContent = (currentIndex + 1) + ' of ' + totalItems
      }

      var navDisabled = totalItems <= 1
      if (prevBtn) prevBtn.style.opacity = navDisabled ? '0.3' : '1'
      if (nextBtn) nextBtn.style.opacity = navDisabled ? '0.3' : '1'

      var isExpanded = container.classList.contains('expanded')
      slides.forEach(function (slide, index) {
        var readMore = slide.querySelector('[data-action="expand"]')
        var collapse = slide.querySelector('[data-action="collapse"]')
        var controls = slide.querySelector('.expand-controls')
        if (!readMore || !collapse) return

        var isOverflowing = !!overflowingStates[index]

        if (controls) controls.classList.toggle('d-none', !isOverflowing)

        if (index === currentIndex) {
          readMore.classList.toggle('d-none', isExpanded || !isOverflowing)
          collapse.classList.toggle('d-none', !isExpanded || !isOverflowing)
        } else {
          readMore.classList.toggle('d-none', !isOverflowing)
          collapse.classList.add('d-none')
        }
      })
    }

    function navigate(direction) {
      try { console.debug('[results-carousel] navigate', { from: currentIndex, direction: direction, totalItems: totalItems }) } catch (e) {}
      if (totalItems === 0) return
      currentIndex += direction
      if (currentIndex < 0) currentIndex = totalItems - 1
      else if (currentIndex >= totalItems) currentIndex = 0
      update()
    }

    function expand() {
      try { console.debug('[results-carousel] expand') } catch (e) {}
      container.classList.add('expanded')
      update()
    }

    function collapse() {
      try { console.debug('[results-carousel] collapse') } catch (e) {}
      container.classList.remove('expanded')
      update()
    }

    function measureOverflow() {
      var wasExpanded = container.classList.contains('expanded')
      if (wasExpanded) container.classList.remove('expanded')

      overflowingStates = slides.map(function (slide) {
        var body = slide.querySelector('.slide-body')
        if (!body) return false
        var isOverflowing = body.scrollHeight > body.clientHeight + 1
        slide.classList.toggle('is-overflowing', isOverflowing)
        return isOverflowing
      })

      if (wasExpanded) container.classList.add('expanded')
      update()
    }

    // Event bindings
    if (prevBtn) prevBtn.addEventListener('click', function () { navigate(-1) })
    if (nextBtn) nextBtn.addEventListener('click', function () { navigate(1) })

    slides.forEach(function (slide) {
      var readMore = slide.querySelector('[data-action="expand"]')
      var collapseBtn = slide.querySelector('[data-action="collapse"]')
      if (readMore) readMore.addEventListener('click', expand)
      if (collapseBtn) collapseBtn.addEventListener('click', collapse)
    })

    measureOverflow()
    window.addEventListener('resize', debounce(measureOverflow, 150))
  }

  function initAllCarousels() {
    var containers = document.querySelectorAll('.text-carousel[data-results-carousel]')
    Array.prototype.forEach.call(containers, function (c) { initResultsCarousel(c) })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAllCarousels)
  } else {
    initAllCarousels()
  }

  window.initResultsCarousel = initResultsCarousel
  function debounce(fn, delay) { var t; return function () { clearTimeout(t); t = setTimeout(fn, delay) } }
})()


