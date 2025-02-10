# frozen_string_literal: true

require 'nokogiri'

module Jekyll
  class TOCGenerator
    def initialize(content)
      @doc = Nokogiri::HTML::DocumentFragment.parse(content)
      @toc = []
      generate_toc(@doc)
    end

    def generate_toc(doc)
      doc.css('h1, h2, h3').each_with_index do |header, index|
        id = "toc-#{index}"
        header['id'] = id
        @toc << { level: header.name, text: header.text, id: id }
      end
    end

    def insert_toc
      return "" if @toc.empty?

      toc_html = "<div class='toc'><h3>Table of Contents</h3><ul>"
      @toc.each do |item|
        indent = " " * (item[:level][-1].to_i * 2)
        toc_html += "#{indent}<li><a href='##{item[:id]}'>#{item[:text]}</a></li>"
      end
      toc_html += "</ul></div>"

      toc_html
    end

    def transformed_content
      insert_toc + @doc.to_html
    end
  end

  class TOCGeneratorHook < Jekyll::Hooks
    Jekyll::Hooks.register :posts, :pre_render do |post|
      if post.data["toc"]
        post.content = TOCGenerator.new(post.content).transformed_content
      end
    end
  end
end
